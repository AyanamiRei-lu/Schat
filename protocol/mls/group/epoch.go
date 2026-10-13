// Package group ties the MLS layers together into an epoch: a tree, its key schedule, its
// transcript and its cached proposals, plus the transition from one epoch to the next.
//
// # What this package is, and is not
//
// It holds NO private keys. A member's keys stay in the client, and the operations here take
// what they need as arguments — a signature public key to verify with, a callback that can
// open path secrets the member is entitled to, the commit secret from the TreeKEM layer.
// That keeps the transition logic testable without a keystore and keeps the question "which
// keys does this member hold" in one place instead of scattered through state transitions.
//
// # One input deliberately not derived here
//
// The commit secret is passed in. It is derived by the TreeKEM layer from the update path's
// secrets, and this project has not read the specification's rule for that derivation yet.
// Inventing it would produce an epoch that agrees with itself and with nothing else — the
// failure this project has hit ten times, always by writing a value from memory instead of
// from the text. Until that rule is read, the layer that owns it supplies the value.
package group

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/schedule"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Epoch is one member's view of the group at one epoch.
type Epoch struct {
	Number  uint64
	Suite   crypto.CipherSuite
	Tree    tree.Tree
	Context schedule.GroupContext
	Secrets schedule.EpochSecrets

	// Transcript is the pair of hash chains. Its confirmed hash is the one the GroupContext
	// carries, so the two must never be updated independently.
	Transcript messages.Transcript

	// Proposals holds what has been received and not yet applied. A commit may cite a proposal
	// by reference, so this has to survive from the epoch the proposal arrived in until the
	// commit that uses it.
	Proposals *messages.ProposalCache

	// PrivateNodes maps a node index to that node's HPKE PRIVATE key. It is LOCAL state: two
	// members of the same epoch hold the same public tree and DIFFERENT private nodes.
	//
	// It exists because the tree cannot hold it — the ratchet tree is shared with everybody, and
	// a private key in it would be published. Section 12.4.3.1 requires a member to set the
	// private key for the nodes on its own direct path, and those keys have to live somewhere
	// that is not the tree.
	//
	// A member without them can SEND but cannot FOLLOW: it can produce a commit, and it cannot
	// process anybody else's, because processing one means decrypting a path secret addressed to
	// it and turning that into node keys. That asymmetry is exactly what every earlier test
	// missed, because they were all driven by the sender.
	PrivateNodes map[uint32][]byte
}

// CommitInput is everything needed to process a commit.
type CommitInput struct {
	WireFormat messages.WireFormat
	Content    *messages.FramedContent

	// Signature is the sender's signature over the content, and ConfirmationTag is the tag
	// that must match the epoch this member computes. Both live in the FramedContentAuthData,
	// and both are required: a commit whose confirmation tag is not checked is a commit whose
	// sender never proved it derived the same group state.
	Signature       []byte
	ConfirmationTag []byte

	// SenderSignatureKey is the sender's public signing key. This package does not look it up:
	// which leaf belongs to which key is a membership question, not a tree question.
	SenderSignatureKey []byte

	// Applier answers whether this member can open a given path-secret ciphertext.
	Applier tree.UpdatePathApplier

	// MyLeaf is the leaf index of the member PROCESSING this commit — not the sender's. A commit
	// is processed by everybody else, and each of them derives a different set of node keys from
	// it, because each occupies a different leaf.
	//
	// It is a new field rather than a new parameter so that existing callers keep compiling: a
	// zero value simply means "this caller does not need the derived keys", which is true of
	// every test written before the receiver side existed.
	MyLeaf uint32

	// KnownSecrets supplies path secrets by NODE INDEX for a caller that already holds them
	// without having to decrypt anything — in practice the member that created the commit,
	// running it through the receiver's validation.
	//
	// It is needed because a path node can legitimately carry NO ciphertexts: when every member
	// of its copath resolution is excluded by this same commit, there is nobody to encrypt to.
	// A receiver then has nothing to open and nothing above it to derive from, so without this
	// the epoch cannot advance — which is exactly the shape of creating a group, where the only
	// member commits and processes its own commit.
	KnownSecrets map[uint32][]byte

	// OriginalTreeHashes are the tree hashes of the CURRENT tree, needed for the parent hash
	// chain of the new one. They cannot be recomputed once the tree has been updated.
	OriginalTreeHashes [][]byte

	// CommitSecret comes from the TreeKEM layer; see the package comment.
	CommitSecret []byte

	// PSKs are the pre-shared keys this commit injects, in the order the commit lists them.
	PSKs []schedule.PSK
}

// ProcessCommit validates a commit against this epoch and returns the next one.
//
// The receiver is left untouched on every failure path: a caller that rejects a commit must
// still hold the epoch it was validating against, and a partially applied commit is worse
// than a rejected one because it cannot be told apart from a valid state.
//
// # The order of operations is forced, not chosen
//
// The three values below depend on each other in a cycle, and the specification breaks it by
// computing them in exactly one order:
//
//  1. confirmed_transcript_hash[N] = Hash(interim[N-1] || commit input). It depends only on
//     the PREVIOUS epoch and the commit, so it can be computed first.
//  2. The new GroupContext carries that confirmed hash, and the key schedule takes the
//     GroupContext, so the epoch's keys come next.
//  3. confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash[N]) — computed from
//     step 2's key and step 1's hash.
//  4. interim_transcript_hash[N] = Hash(confirmed[N] || confirmation_tag) closes the cycle,
//     and is what the NEXT epoch's step 1 will consume.
//
// An implementation that folded the tag in earlier, or that advanced the transcript with a
// placeholder, would produce a chain that verifies against itself and against no other
// member: the tag is both computed from and folded into the transcript, so getting the order
// wrong is invisible locally.
func (e *Epoch) ProcessCommit(in CommitInput) (*Epoch, error) {
	if in.Content == nil {
		return nil, fmt.Errorf("mls/group: no commit content")
	}
	if in.Content.Type != messages.ContentTypeCommit {
		return nil, fmt.Errorf("mls/group: content type %d is not a commit", in.Content.Type)
	}
	if in.Content.Commit == nil {
		return nil, fmt.Errorf("mls/group: a commit content with no commit")
	}

	// A commit that opens epoch N is sent in epoch N-1, so its own epoch field must equal this
	// member's current epoch. A commit claiming the new epoch number belongs to the future; one
	// claiming an older epoch is a replay.
	if in.Content.Epoch != e.Number {
		return nil, fmt.Errorf("mls/group: the commit is for epoch %d but this member is in %d",
			in.Content.Epoch, e.Number)
	}

	contextBytes, err := e.Context.Marshal()
	if err != nil {
		return nil, err
	}

	if err := messages.VerifyFramedContentSignature(in.WireFormat, in.Content, contextBytes,
		in.SenderSignatureKey, in.Signature, e.Suite); err != nil {
		return nil, err
	}

	// Step 1: the confirmed transcript hash of the epoch being opened.
	confirmedInput, err := messages.ConfirmedTranscriptHashInput(in.WireFormat, in.Content, in.Signature)
	if err != nil {
		return nil, err
	}
	confirmed := e.Suite.Hash(concat(e.Transcript.Interim, confirmedInput))

	// The tree changes.
	// Filled by applyProposalsAndPath with the node keys this member derives; see its comment.
	newPrivateNodes := map[uint32][]byte{}

	updated, err := e.applyProposalsAndPath(&in, newPrivateNodes)
	if err != nil {
		return nil, err
	}

	newTreeHash, err := treeHashOf(updated, e.Suite)
	if err != nil {
		return nil, err
	}

	pskSecret, err := schedule.PSKSecret(in.PSKs, e.Suite)
	if err != nil {
		return nil, err
	}

	nextContext := e.Context
	nextContext.Epoch = e.Number + 1
	nextContext.TreeHash = newTreeHash
	nextContext.ConfirmedTranscriptHash = confirmed

	// Step 2: the new epoch's keys, which the confirmation tag is computed from.
	// Section 12.4.1: a commit that carries NO path defines the commit secret as the
	// all-zero vector of KDF.Nh. That is decidable from the commit alone, which matters
	// because a receiver cannot derive it — there is no path to derive it from — and a
	// receiver that fed nil into the key schedule would compute a different epoch from
	// identical state and fail at the confirmation tag.
	if len(in.CommitSecret) == 0 && (in.Content.Commit == nil || in.Content.Commit.Path == nil) {
		in.CommitSecret = make([]byte, e.Suite.HashSize())
	}

	secrets, err := schedule.KeySchedule(e.Secrets.InitSecret, in.CommitSecret, pskSecret,
		nextContext, e.Suite)
	if err != nil {
		return nil, err
	}

	// Step 3 and the check: the tag must be the one this member computed. This is the only
	// check that proves the sender derived the same epoch, so it is not optional and it is not
	// left for the caller to remember.
	wantTag, err := messages.ConfirmationTag(secrets.ConfirmationKey, confirmed, e.Suite)
	if err != nil {
		return nil, err
	}
	if len(in.ConfirmationTag) == 0 {
		return nil, fmt.Errorf("mls/group: the commit carries no confirmation tag, so its sender " +
			"never confirmed the epoch it is opening")
	}
	if !equalBytes(wantTag, in.ConfirmationTag) {
		return nil, fmt.Errorf("mls/group: the confirmation tag does not match the epoch this " +
			"member computed, so the sender derived different group state")
	}

	// Step 4: close the chain for the next epoch.
	interimInput, err := messages.InterimTranscriptHashInput(in.ConfirmationTag)
	if err != nil {
		return nil, err
	}
	interim := e.Suite.Hash(concat(confirmed, interimInput))

	// The node keys this member derived from the commit, which the tree layer computed and had
	// nowhere to keep. Without them the member processes this commit and no later one.

	return &Epoch{
		PrivateNodes: newPrivateNodes,
		Number:       e.Number + 1,
		Suite:        e.Suite,
		Tree:         updated,
		Context:      nextContext,
		Secrets:      secrets,
		Transcript:   messages.Transcript{Confirmed: confirmed, Interim: interim},
		Proposals:    messages.NewProposalCache(e.Suite),
	}, nil
}

// applyProposalsAndPath returns the tree the commit produces, without modifying this epoch's.
// privateNodes is filled with the private keys this member derives from the commit's path. It is
// an out-parameter rather than a third return value because a signature change would ripple
// through every failure return in this function, and every caller — the same trade this project
// already made once, after a signature change broke a test file.
func (e *Epoch) applyProposalsAndPath(in *CommitInput, privateNodes map[uint32][]byte) (tree.Tree, error) {
	current := make(tree.Tree, len(e.Tree))
	copy(current, e.Tree)

	// The leaves this commit adds. They must be kept out of the path's recipients: a new member
	// learns the epoch through its Welcome, so a path secret sent to it would hand key material
	// to somebody who is not in the epoch it belongs to.
	var addedLeaves []uint32

	for _, ref := range in.Content.Commit.Proposals {
		if ref == nil {
			return nil, fmt.Errorf("mls/group: the commit contains a nil proposal reference")
		}
		if ref.Proposal == nil {
			// A by-reference proposal has to be resolved from the cache and supplied inline.
			// Refusing is better than skipping it: a commit that silently applied fewer
			// proposals than it listed would leave two members in different states, and the
			// confirmation tag would be the only thing that noticed.
			return nil, fmt.Errorf("mls/group: the commit cites a proposal by reference; resolve " +
				"it from the cache and supply it inline before processing")
		}

		switch ref.Proposal.Type {
		case messages.ProposalTypeRemove:
			if ref.Proposal.Remove == nil {
				return nil, fmt.Errorf("mls/group: a Remove proposal with no leaf index")
			}
			node := 2 * ref.Proposal.Remove.Removed
			if int(node) >= len(current) {
				return nil, fmt.Errorf("mls/group: Remove refers to leaf %d, outside a tree of %d nodes",
					ref.Proposal.Remove.Removed, len(current))
			}
			if current[node] == nil {
				return nil, fmt.Errorf("mls/group: Remove refers to leaf %d, which is already blank",
					ref.Proposal.Remove.Removed)
			}
			// Removing a member blanks its leaf. The hole stays in the tree, which is what
			// keeps the tree's shape and every other member's position unchanged.
			current[node] = nil

		case messages.ProposalTypeAdd:
			if ref.Proposal.Add == nil || ref.Proposal.Add.KeyPackage == nil {
				return nil, fmt.Errorf("mls/group: an Add proposal with no KeyPackage")
			}
			keyPackage := ref.Proposal.Add.KeyPackage

			// The package must describe THIS group: a package for another version or another
			// ciphersuite would put a member in the tree whose keys nothing here can use, and
			// the mismatch would surface much later as a member that cannot read anything.
			if err := messages.VerifyKeyPackage(keyPackage, e.Context.Version,
				e.Context.CipherSuite, e.Suite); err != nil {
				return nil, err
			}

			// A new member needs a leaf slot, and the tree grows only when there is none: the
			// specification adds leaves at the right edge, so a tree with a hole has room and
			// does not need a new level.
			needsExtension, err := tree.NeedsExtension(current)
			if err != nil {
				return nil, err
			}
			if needsExtension {
				current, err = tree.Extend(current)
				if err != nil {
					return nil, fmt.Errorf("mls/group: extending the tree for an Add: %w", err)
				}
			}

			slot, ok, err := tree.FirstFreeLeaf(current)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("mls/group: no free leaf slot for an Add even after extending")
			}
			current[2*slot] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: keyPackage.LeafNode}
			addedLeaves = append(addedLeaves, slot)

		case messages.ProposalTypeUpdate:
			// An Update's effect is the sender's new leaf node, which travels in the path
			// rather than in the proposal. Nothing to apply here.

		default:
			return nil, fmt.Errorf("mls/group: proposal type %d cannot be applied by this implementation",
				ref.Proposal.Type)
		}
	}

	if in.Content.Commit.Path != nil {
		// The leaves this commit removes are kept out of the path's recipients on this side too.
		// A receiver that expected a ciphertext the sender deliberately did not send would
		// reject a correct commit; one that expected nothing and got something would hand a
		// secret to a member being removed.
		var effects []tree.ProposalEffect
		for _, ref := range in.Content.Commit.Proposals {
			if ref == nil || ref.Proposal == nil {
				continue
			}
			if ref.Proposal.Type == messages.ProposalTypeRemove && ref.Proposal.Remove != nil {
				removed := ref.Proposal.Remove.Removed
				effects = append(effects, tree.ProposalEffect{RemovedLeaf: &removed})
			}
		}
		if len(addedLeaves) > 0 {
			effects = append(effects, tree.ProposalEffect{AddedLeaves: addedLeaves})
		}
		excluded := tree.ExcludedLeavesForCommit(effects)

		// Computed here rather than taken from the caller: the hashes must describe the tree
		// the path extends — proposals applied, path not — and only this function has that
		// tree. A caller passing pre-commit hashes is right only while the commit leaves the
		// tree's shape alone, which an Add does not.
		originalHashes, err := tree.TreeHashes(current, e.Suite)
		if err != nil {
			return nil, err
		}

		// The path secret addressed to THIS member is captured on its way past. The tree layer
		// decrypts it, uses it to rebuild the path, and has nowhere to keep it — and it is the
		// input to this member's own private node keys.
		var captured []byte
		capturingApplier := func(member uint32, ct tree.HPKECiphertext) ([]byte, bool) {
			secret, ok := in.Applier(member, ct)
			if ok && captured == nil {
				captured = secret
			}
			return secret, ok
		}

		// The commit secret is the ROOT's path secret, which only the path application knows.
		// A receiver is not given it; it derives it here or it does not have it at all.
		var derivedCommitSecret []byte
		applied, err := tree.ApplyUpdatePathExcluding(current, in.Content.Sender.LeafIndex,
			in.Content.Commit.Path, excluded, in.KnownSecrets, capturingApplier, originalHashes, e.Suite, &derivedCommitSecret)

		// The commit secret is an INPUT to the key schedule and an OUTPUT of applying the
		// path: a receiver is not given it, it derives it. Filling it here is what makes the
		// two sides agree — without it the tree is rebuilt correctly and the epoch keys are
		// wrong, which shows up as a confirmation tag that does not match and looks like a
		// cryptographic fault rather than a missing input.
		// Section 12.4.1: when the commit carries NO path, the commit secret is the all-zero
		// vector of length KDF.Nh — the same value the sender used, which is why the two sides
		// agree on an epoch that nothing was derived for. Without this branch a receiver of a
		// pathless commit feeds nil into the key schedule, derives a different epoch from
		// identical state, and fails at the confirmation tag.
		if len(in.CommitSecret) == 0 {
			if len(derivedCommitSecret) > 0 {
				in.CommitSecret = derivedCommitSecret
			} else {
				in.CommitSecret = make([]byte, e.Suite.HashSize())
			}
		}

		// Section 12.4.3.1, and the SAME function a joining member uses: the derivation is
		// identical whether the path secret arrived in a Welcome or in a commit, and keeping one
		// implementation is what stops the two from drifting apart.
		if err == nil && len(captured) > 0 && privateNodes != nil {
			derived, derr := derivePrivateNodes(applied, in.MyLeaf, in.Content.Sender.LeafIndex,
				e.PrivateNodes[2*in.MyLeaf], captured, e.Suite)
			if derr != nil {
				return nil, derr
			}
			for node, key := range derived {
				privateNodes[node] = key
			}
		}
		if err != nil {
			return nil, fmt.Errorf("mls/group: applying the update path: %w", err)
		}
		current = applied
	}

	// The tree is truncated when a removal left the root's right subtree entirely blank. Both
	// this path and the sender's must apply it: calling it in only one would make the two sides
	// disagree with each other as well as with every other implementation.
	return TruncateIfTheRightSubtreeIsBlank(current)
}

// treeHashOf returns the tree hash of the root of a tree in the array layout.
func treeHashOf(t tree.Tree, suite crypto.CipherSuite) ([]byte, error) {
	leaves, err := tree.LeavesForLayout(uint32(len(t)))
	if err != nil {
		return nil, err
	}
	root, err := tree.Root(leaves)
	if err != nil {
		return nil, err
	}
	return tree.TreeHash(t, root, suite)
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
