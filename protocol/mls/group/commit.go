package group

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/schedule"
	"github.com/schat/schat/protocol/mls/tree"
)

// Creating a commit (RFC 9420 sections 7.5, 7.6 and 12.4).
//
// # The sender's problem is the receiver's in reverse, except for one step
//
// A receiver derives the epoch from a commit it was given. A sender has to derive the epoch
// first, because the confirmation tag it must send is computed from that epoch's confirmation
// key — so the sender cannot ask the receiver's code path for it, and the order is fixed:
//
//	path secrets and node keys  ->  apply the path  ->  new tree hash
//	  ->  confirmed transcript hash  ->  new GroupContext  ->  new epoch keys
//	  ->  confirmation tag  ->  sign the content
//
// Note where the signature sits: LAST. The confirmed transcript hash covers the commit's
// signature, so the signature has to exist before the hash that the tag is computed from —
// and the signature covers the content, whose epoch field is the CURRENT epoch, not the one
// being opened.
//
// # Reusing the receiver's tree update rather than writing a second one
//
// The sender ends up with the same tree the receiver will build, so this function calls
// ApplyUpdatePath — the verified receiver-side code — instead of reimplementing the key
// replacement, the parent hash chain and the copath child update. The sender is a recipient
// of every path secret it generated, so it can answer the applier callback from the secrets
// it already holds. A second implementation of that update would be a second chance to get
// the copath children wrong, and the first one only got them right because a test caught it.

// CommitSpec is what a member supplies to create a commit.
type CommitSpec struct {
	WireFormat messages.WireFormat

	// SenderLeaf is the committing member's leaf index.
	SenderLeaf uint32

	// SenderSigningKey is that member's PRIVATE signing key.
	SenderSigningKey []byte

	// Proposals are applied by the commit, inline. An empty list with a path is a self-update,
	// which is how a member refreshes its own key material.
	Proposals []*messages.ProposalOrRef

	// NewLeafNode is the sender's new leaf node. Required when the commit carries a path;
	// it is what the path's secrets will be published under.
	NewLeafNode *tree.LeafNode

	// NewLeafPrivate is the private half of the key in NewLeafNode. It is needed because the
	// commit REPLACES the sender's own leaf: after it, the sender's usable key is this new one,
	// and a member that did not keep it would hold a key its leaf no longer publishes — able to
	// send this commit and unable to follow the next one from anybody else.
	//
	// It is the mirror of the gap that kept the CREATOR from following commits, and the same
	// shape as the one that kept a joining member from doing so.
	NewLeafPrivate []byte

	// PathSecret is fresh randomness, KDF.Nh bytes, from which every secret on the path is
	// derived. Supplied rather than generated here so a caller can source it from an audited
	// random number generator, and so a test can be deterministic.
	PathSecret []byte

	// PSKs are injected in this order.
	PSKs []schedule.PSK

	// ExcludeFromPath are leaves added by this same commit. They must not receive path secrets
	// — they learn the epoch through the Welcome instead — and a secret sent to a member who
	// is not yet in the epoch it belongs to is a disclosure, not a bookkeeping error.
	ExcludeFromPath []uint32
}

// CreatedCommit is a commit ready to send, together with the sender's new epoch.
type CreatedCommit struct {
	WireFormat      messages.WireFormat
	Content         *messages.FramedContent
	Signature       []byte
	ConfirmationTag []byte

	// Next is the epoch the sender moves to once the commit is accepted. The sender holds it
	// from the moment it sends, because it cannot continue in the old epoch either.
	Next *Epoch

	// KnownSecrets are the path secrets this commit was built from, keyed by NODE INDEX.
	//
	// They travel with the commit because the sender needs them to validate its own work: a
	// path node can carry no ciphertexts at all when every member of its copath resolution is
	// excluded, and then nothing can be decrypted and the secrets are the only way to advance.
	// Without them a one-member group — which is what creating a group produces — could not
	// process its own commit.
	KnownSecrets map[uint32][]byte

	// AddedLeaves are the leaf indices this commit placed new members at, in the NEW tree.
	//
	// It travels with the commit because the sender needs it to build the Welcome: the path
	// secret a new member receives is the one belonging to the lowest node on the direct paths
	// of that member and the committer, and finding it starts with knowing where the member
	// landed. CreateCommit already computes this — the placement is part of applying the
	// proposals — and leaving it inside would force every caller to recompute the tree's
	// placement rule, which is the kind of duplication that ends with two answers.
	AddedLeaves []uint32
}

// CreateCommit builds, signs and tags a commit.
//
// It returns an error rather than a partially built commit at every step: a commit that is
// missing its path, or whose tag does not match the epoch it opens, would be accepted by
// nobody and would leave the sender unable to explain why.
func (e *Epoch) CreateCommit(spec CommitSpec) (*CreatedCommit, error) {
	// The commit secret is derived below, from the path this commit generates. It is not a
	// parameter: a caller-chosen value cannot be reproduced by any receiver, and offering
	// one made every test that passed it to a receiver test something that cannot happen.
	var commitSecret []byte
	if spec.NewLeafNode == nil {
		return nil, fmt.Errorf("mls/group: a commit must carry a new leaf node for its sender")
	}
	if len(spec.PathSecret) != e.Suite.HashSize() {
		return nil, fmt.Errorf("mls/group: the path secret is %d bytes, want %d",
			len(spec.PathSecret), e.Suite.HashSize())
	}

	contextBytes, err := e.Context.Marshal()
	if err != nil {
		return nil, err
	}

	// The tree the path is generated against: the current one with the sender's leaf replaced
	// by its new leaf node, so that the path publishes the key the sender is moving to.
	// The proposals first, then the sender's own leaf: the path must be generated on the tree the
	// commit actually produces, with any added member already placed. The earlier version placed
	// only the sender's leaf, so a commit adding a member produced a tree without that member --
	// and the receiver, which does place it, computed a different tree hash.
	working, addedLeaves, err := applyProposalEffects(e.Tree, spec.Proposals,
		e.Context.Version, e.Context.CipherSuite, e.Suite)
	if err != nil {
		return nil, err
	}

	withNewLeaf := make(tree.Tree, len(working))
	copy(withNewLeaf, working)

	// The "original" tree hashes are those of the tree the path EXTENDS: the proposals are
	// applied, the path is not. They used to be taken from the epoch's tree, before the
	// proposals, which is the same thing only while a commit leaves the tree's shape alone —
	// and an Add does not.
	originalHashes, err := tree.TreeHashes(working, e.Suite)
	if err != nil {
		return nil, err
	}
	node := 2 * spec.SenderLeaf
	if int(node) >= len(withNewLeaf) {
		return nil, fmt.Errorf("mls/group: leaf %d is outside a tree of %d nodes",
			spec.SenderLeaf, len(withNewLeaf))
	}
	withNewLeaf[node] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: spec.NewLeafNode}

	// The leaves this commit removes must not receive path secrets, or the removal leaves them
	// able to derive the new epoch — and nothing reports it.
	//
	// This has to be computed BEFORE the path is generated, and passed to it. The first version
	// computed it only for the apply step below, so the path still encrypted a secret to the
	// member being removed while the apply step expected no ciphertext for it: the commit
	// contradicted itself and could not be created at all. A test caught it immediately, which
	// is the point of writing the removal case end to end rather than trusting the two halves
	// to agree.
	var effects []tree.ProposalEffect
	for _, ref := range spec.Proposals {
		if ref == nil || ref.Proposal == nil {
			return nil, fmt.Errorf("mls/group: a commit cannot be built from an unresolved " +
				"proposal reference")
		}
		switch ref.Proposal.Type {
		case messages.ProposalTypeRemove:
			if ref.Proposal.Remove == nil {
				return nil, fmt.Errorf("mls/group: a Remove proposal with no leaf index")
			}
			removed := ref.Proposal.Remove.Removed
			effects = append(effects, tree.ProposalEffect{RemovedLeaf: &removed})
		default:
			// A proposal that does not change the tree's leaves excludes nothing.
			effects = append(effects, tree.ProposalEffect{})
		}
	}
	excluded := tree.ExcludedLeavesForCommit(effects)

	// The caller's own exclusions (leaves this commit adds) are added to the ones the proposals
	// imply, because both must be kept out of the path.
	for _, node := range spec.ExcludeFromPath {
		excluded[node] = true
	}
	// A member added by this commit learns the epoch through its Welcome, so it must not be a
	// path recipient. The indices come back from applyProposalEffects because the committer
	// decides WHERE a new member goes, and only that function knows.
	for _, leaf := range addedLeaves {
		excluded[2*leaf] = true
	}

	path, err := tree.GenerateUpdatePath(withNewLeaf, spec.SenderLeaf, contextBytes,
		spec.PathSecret, setToSlice(excluded), e.Suite)
	if err != nil {
		return nil, fmt.Errorf("mls/group: generating the update path: %w", err)
	}

	// Section 12.4.1: when there is no path, the commit secret is the all-zero vector of KDF.Nh.
	//
	// The caller cannot make this choice, because it cannot know whether a path exists — the
	// decision belongs to whoever generated it. A caller passing a random secret, as the natural
	// reading of CommitSpec suggests, would set the sender's epoch and nobody else's.
	//
	// The zero vector is not a weakness: what makes the epoch secret unpredictable is the INIT
	// secret it is extracted with, not this. A zero here contributes nothing and hides nothing.
	if path.Path == nil {
		commitSecret = make([]byte, e.Suite.HashSize())
	}

	content := &messages.FramedContent{
		GroupID: e.Context.GroupID,
		Epoch:   e.Number,
		Sender:  messages.Sender{Type: messages.SenderTypeMember, LeafIndex: spec.SenderLeaf},
		Type:    messages.ContentTypeCommit,
		Commit:  &messages.Commit{Proposals: spec.Proposals, Path: path.Path},
	}

	// The signature must exist before the confirmed transcript hash, because that hash covers
	// it.
	signature, err := messages.SignFramedContent(spec.WireFormat, content, contextBytes,
		spec.SenderSigningKey, e.Suite)
	if err != nil {
		return nil, fmt.Errorf("mls/group: signing the commit: %w", err)
	}

	confirmedInput, err := messages.ConfirmedTranscriptHashInput(spec.WireFormat, content, signature)
	if err != nil {
		return nil, err
	}
	confirmed := e.Suite.Hash(concat(e.Transcript.Interim, confirmedInput))

	// The sender's own tree, built with the receiver's code, with the secrets it holds supplied
	// by NODE INDEX. Keying them on the ciphertexts it had produced failed exactly when a path
	// node carried none — the case where every member of its copath resolution was excluded, as
	// happens when a commit removes the last other member of a two-leaf group. That commit
	// could not be created at all, and the self-update case hid it because there the resolution
	// is never empty.
	knownSecrets := map[uint32][]byte{}
	for i, pathNode := range path.FilteredPath {
		knownSecrets[pathNode] = path.PathSecrets[i]
	}

	// The removals must land in the sender's own tree too, not only in the path's exclusions.
	// The first version applied the path without applying the proposals, so the sender kept the
	// removed member's leaf and would have disagreed with every receiver about the new tree
	// hash — a disagreement the confirmation tag would then report as "the sender derived
	// different group state", pointing nowhere near the missing step.
	// The working tree already has the proposals applied, so the path is applied to it rather
	// than to a second copy with the removals repeated.
	beforePath := working
	for _, effect := range effects {
		if effect.RemovedLeaf == nil {
			continue
		}
		node := 2 * *effect.RemovedLeaf
		if int(node) >= len(beforePath) {
			return nil, fmt.Errorf("mls/group: Remove refers to leaf %d, outside a tree of %d nodes",
				*effect.RemovedLeaf, len(beforePath))
		}
		beforePath[node] = nil
	}

	// With no path there is nothing to apply: the sender's tree after the commit IS the working
	// tree, which already carries every proposal — including the sender's own new leaf, placed
	// while the path was being generated.
	//
	// This is the second place that assumed a commit always has a path. The assumption holds for
	// every group with two or more members, which is why every existing test passed while a
	// one-member group could not add anybody. Passing a null optional path into the tree layer
	// is not a harmless no-op it can absorb: there is no leaf node inside it to apply.
	var applied tree.Tree
	if path.Path == nil {
		applied = beforePath
	} else {
		// The sender passes no map: it already holds these keys, straight from the generator
		// (path.NodePrivateKeys), and asking the applier to hand them back would be a second
		// route to the same state — the kind that diverges.
		applied, err = tree.ApplyUpdatePathExcluding(beforePath, spec.SenderLeaf, path.Path, excluded,
			knownSecrets, nil, originalHashes, e.Suite, nil)
		if err != nil {
			return nil, fmt.Errorf("mls/group: applying its own path: %w", err)
		}
	}

	// Truncate first, then hash: the tree hash must describe the tree that results from the
	// commit, and after a removal that tree may have lost its whole right half.
	applied, err = TruncateIfTheRightSubtreeIsBlank(applied)
	if err != nil {
		return nil, fmt.Errorf("mls/group: truncating the tree after the commit: %w", err)
	}

	newTreeHash, err := treeHashOf(applied, e.Suite)
	if err != nil {
		return nil, err
	}

	pskSecret, err := schedule.PSKSecret(spec.PSKs, e.Suite)
	if err != nil {
		return nil, err
	}

	nextContext := e.Context
	nextContext.Epoch = e.Number + 1
	nextContext.TreeHash = newTreeHash
	nextContext.ConfirmedTranscriptHash = confirmed

	// The commit secret comes FROM THE PATH, not from the caller. Section 12.4.1 gives the
	// pathless case the all-zero vector; with a path it is the last secret the generator
	// produced, which is the root's path secret. A caller-chosen value cannot be
	// reproduced by any receiver, and the two sides then derive different epochs from
	// identical state — visible only to a test that does not hand the receiver the
	// sender's secret, which is why the faithful tests are the ones that fail.
	if path.Path != nil && len(path.PathSecrets) > 0 {
		commitSecret = path.PathSecrets[len(path.PathSecrets)-1]
	}

	secrets, err := schedule.KeySchedule(e.Secrets.InitSecret, commitSecret, pskSecret,
		nextContext, e.Suite)
	if err != nil {
		return nil, err
	}

	tag, err := messages.ConfirmationTag(secrets.ConfirmationKey, confirmed, e.Suite)
	if err != nil {
		return nil, err
	}

	interimInput, err := messages.InterimTranscriptHashInput(tag)
	if err != nil {
		return nil, err
	}

	// The private state of the new epoch is the OLD one plus what this path generated. The
	// member's own leaf key stays valid across an epoch — its leaf is only replaced when the
	// member itself updates — and assigning instead of merging wiped it on every commit
	// whose path was empty, which is exactly the one-member case a group starts in.
	mergedPrivateNodes := make(map[uint32][]byte, len(e.PrivateNodes)+len(path.NodePrivateKeys))
	for node, key := range e.PrivateNodes {
		mergedPrivateNodes[node] = key
	}
	for node, key := range path.NodePrivateKeys {
		mergedPrivateNodes[node] = key
	}
	// The sender's own leaf was just replaced, so its NEW key goes in and the old one is gone:
	// the merge above would otherwise leave the previous key in place, and a member holding a key
	// its leaf no longer publishes is in the same position as one holding none.
	if len(spec.NewLeafPrivate) > 0 {
		mergedPrivateNodes[2*spec.SenderLeaf] = spec.NewLeafPrivate
	}

	return &CreatedCommit{
		// The placement the caller needs to build the Welcome; see the field's comment.
		AddedLeaves:     addedLeaves,
		WireFormat:      spec.WireFormat,
		Content:         content,
		Signature:       signature,
		ConfirmationTag: tag,
		Next: &Epoch{
			// 发送方自己的私有状态：本提交刚刚生成的节点私钥。没有它们，它能产出这一条提交，
			// 却跟不上任何别人的提交——而这不影响它自己看起来一切正常。
			PrivateNodes: mergedPrivateNodes,
			Number:       e.Number + 1,
			Suite:        e.Suite,
			Tree:         applied,
			Context:      nextContext,
			Secrets:      secrets,
			Transcript:   messages.Transcript{Confirmed: confirmed, Interim: e.Suite.Hash(concat(confirmed, interimInput))},
			Proposals:    messages.NewProposalCache(e.Suite),
		},
		KnownSecrets: knownSecrets,
	}, nil
}

// AsInput turns a created commit into what ProcessCommit consumes, so that a member can run
// its own commit through the same validation path a receiver will.
//
// Doing that is not ceremony: a sender that never validates its own commit ships whatever its
// bugs produced, and the first sign of trouble is every other member rejecting it. Running it
// locally turns that into an error at the sender.
func (c *CreatedCommit) AsInput(senderSignatureKey []byte, commitSecret []byte, applier tree.UpdatePathApplier, originalHashes [][]byte, psks []schedule.PSK) CommitInput {
	return CommitInput{
		WireFormat:         c.WireFormat,
		Content:            c.Content,
		Signature:          c.Signature,
		ConfirmationTag:    c.ConfirmationTag,
		SenderSignatureKey: senderSignatureKey,
		Applier:            applier,
		OriginalTreeHashes: originalHashes,
		CommitSecret:       commitSecret,
		PSKs:               psks,
		// KnownSecrets is deliberately NOT set here. AsInput models how ANOTHER member sees this
		// commit, and another member holds none of the sender's path secrets — it has to open
		// them from the ciphertexts. Filling this in would silently turn every receiver test
		// into a sender test, which is exactly what happened when it was first added: three
		// tests that check a receiver decrypts its own secret stopped exercising that path.
		// A sender validating its own work sets the field on the result; see SelfInput.
	}
}

// SelfInput is the sender's view of its own commit: the same input a receiver gets, plus the
// path secrets the sender built the path from.
//
// The two are kept apart because they are genuinely different situations. A receiver must
// decrypt; a sender must not have to. A single constructor that guessed which one the caller
// meant would make the receiver tests pass for the wrong reason.
func (c *CreatedCommit) SelfInput(senderSignatureKey []byte, commitSecret []byte, applier tree.UpdatePathApplier, originalHashes [][]byte, psks []schedule.PSK) CommitInput {
	in := c.AsInput(senderSignatureKey, commitSecret, applier, originalHashes, psks)
	in.KnownSecrets = c.KnownSecrets
	return in
}

// setToSlice flattens an exclusion set for the generator, whose signature takes a slice.
//
// The set is the right shape for the caller — the same node may be excluded for two reasons —
// and the slice is the right shape for the generator, which only iterates. Converting here
// rather than widening the generator's type keeps that function's contract simple: a set would
// imply it might modify what it is given.
func setToSlice(set map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(set))
	for node := range set {
		out = append(out, node)
	}
	return out
}
