package messages

import (
	"bytes"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
	"github.com/schat/schat/protocol/mls/tree"
)

// suiteUnderTest is the cipher suite the official vectors use for the structures this package
// builds on, so the hashes computed here are comparable with the ones verified elsewhere.
const suiteUnderTest = crypto.CipherSuite(0x0001)

// The tests here are the first verification of the message layer. There are no official
// byte-exact vectors for these structures, so the evidence is round-tripping (encode, decode,
// re-encode, compare) plus the negative cases: an encoding that accepts everything is not
// evidence of anything.

func sampleLeafNode() *tree.LeafNode {
	return &tree.LeafNode{
		EncryptionKey: bytes.Repeat([]byte{0xA1}, 32),
		SignatureKey:  bytes.Repeat([]byte{0xB2}, 32),
		Credential: tree.Credential{
			Type:     tree.CredentialTypeBasic,
			Identity: []byte("alice"),
		},
		Capabilities: tree.Capabilities{
			Versions:     []uint16{1},
			CipherSuites: []uint16{1, 3},
			Proposals:    []uint16{},
			Credentials:  []uint16{1},
		},
		Source:     tree.LeafNodeSourceUpdate,
		Extensions: []tree.Extension{{Type: 2, Data: []byte{0x01}}},
		Signature:  bytes.Repeat([]byte{0xC3}, 64),
	}
}

func sampleProposal(t *testing.T, kind ProposalType) *Proposal {
	t.Helper()
	switch kind {
	case ProposalTypeUpdate:
		return &Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: sampleLeafNode()}}
	case ProposalTypeRemove:
		return &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 7}}
	default:
		t.Fatalf("no sample for proposal type %d", kind)
		return nil
	}
}

// roundTrip encodes, decodes and re-encodes, reporting where the two encodings differ.
func roundTrip(t *testing.T, name string, encode func(*mlstls.Writer) error,
	decode func(*mlstls.Reader) error) []byte {
	t.Helper()

	w := mlstls.NewWriter(512)
	if err := encode(w); err != nil {
		t.Fatalf("%s: encoding: %v", name, err)
	}
	if err := w.Err(); err != nil {
		t.Fatalf("%s: encoding: %v", name, err)
	}
	first := w.Bytes()

	if err := decode(mlstls.NewReader(first)); err != nil {
		t.Fatalf("%s: decoding its own output: %v", name, err)
	}

	w2 := mlstls.NewWriter(512)
	if err := encode(w2); err != nil {
		t.Fatalf("%s: re-encoding: %v", name, err)
	}
	second := w2.Bytes()

	if !bytes.Equal(first, second) {
		t.Fatalf("%s: the round trip changed the bytes\n  first:  %x\n  second: %x",
			name, first, second)
	}
	return first
}

func TestProposalRoundTrip(t *testing.T) {
	for _, kind := range []ProposalType{ProposalTypeUpdate, ProposalTypeRemove} {
		proposal := sampleProposal(t, kind)

		var decoded *Proposal
		encoded := roundTrip(t, "proposal", proposal.Marshal, func(r *mlstls.Reader) error {
			p, err := ParseProposal(r)
			decoded = p
			return err
		})

		if decoded == nil {
			t.Fatalf("proposal type %d decoded to nothing", kind)
		}
		if decoded.Type != kind {
			t.Fatalf("proposal type became %d", decoded.Type)
		}
		if kind == ProposalTypeRemove && decoded.Remove.Removed != 7 {
			t.Fatalf("the removed leaf index became %d", decoded.Remove.Removed)
		}
		if len(encoded) == 0 {
			t.Fatal("a proposal encoded to nothing")
		}
	}
}

func TestFramedContentRoundTrip(t *testing.T) {
	commitWithPath := &Commit{
		Proposals: []*ProposalOrRef{
			{Type: ProposalOrRefTypeProposal, Proposal: sampleProposal(t, ProposalTypeRemove)},
			{Type: ProposalOrRefTypeReference, Reference: bytes.Repeat([]byte{0xD4}, 32)},
		},
		Path: &tree.UpdatePath{
			LeafNode: sampleLeafNode(),
			Nodes: []tree.UpdatePathNode{{
				EncryptionKey: bytes.Repeat([]byte{0xE5}, 32),
				EncryptedPathSecret: []tree.HPKECiphertext{{
					KemOutput:  bytes.Repeat([]byte{0x11}, 32),
					Ciphertext: bytes.Repeat([]byte{0x22}, 48),
				}},
			}},
		},
	}

	cases := []struct {
		name    string
		content *FramedContent
	}{
		{"application", &FramedContent{
			GroupID: []byte("group"), Epoch: 5,
			Sender:            Sender{Type: SenderTypeMember, LeafIndex: 3},
			AuthenticatedData: []byte("ad"),
			Type:              ContentTypeApplication,
			ApplicationData:   []byte("hello"),
		}},
		{"proposal", &FramedContent{
			GroupID: []byte("group"), Epoch: 5,
			Sender:   Sender{Type: SenderTypeMember, LeafIndex: 3},
			Type:     ContentTypeProposal,
			Proposal: sampleProposal(t, ProposalTypeUpdate),
		}},
		{"commit with a path", &FramedContent{
			GroupID: []byte("group"), Epoch: 5,
			Sender: Sender{Type: SenderTypeMember, LeafIndex: 3},
			Type:   ContentTypeCommit,
			Commit: commitWithPath,
		}},
		{"commit without a path", &FramedContent{
			GroupID: []byte("group"), Epoch: 6,
			Sender: Sender{Type: SenderTypeMember, LeafIndex: 0},
			Type:   ContentTypeCommit,
			Commit: &Commit{
				Proposals: []*ProposalOrRef{
					{Type: ProposalOrRefTypeProposal, Proposal: sampleProposal(t, ProposalTypeRemove)},
				},
			},
		}},
		{"external sender", &FramedContent{
			GroupID: []byte("group"), Epoch: 0,
			Sender:          Sender{Type: SenderTypeExternal, SenderIndex: 9},
			Type:            ContentTypeApplication,
			ApplicationData: []byte("from outside"),
		}},
	}

	for _, tc := range cases {
		var decoded *FramedContent
		roundTrip(t, tc.name, tc.content.Marshal, func(r *mlstls.Reader) error {
			c, err := ParseFramedContent(r)
			decoded = c
			return err
		})

		if decoded == nil || decoded.Type != tc.content.Type {
			t.Fatalf("%s: content type did not survive", tc.name)
		}
		if decoded.Epoch != tc.content.Epoch {
			t.Fatalf("%s: epoch %d became %d", tc.name, tc.content.Epoch, decoded.Epoch)
		}
		if decoded.Sender.Type != tc.content.Sender.Type {
			t.Fatalf("%s: sender type did not survive", tc.name)
		}
	}
}

// TestCommitPathPresenceIsEncoded checks the optional field explicitly, because a commit that
// carries no path and one that carries an empty path look the same in a struct and are not
// the same on the wire: one is a zero byte, the other is a present byte followed by a length.
func TestCommitPathPresenceIsEncoded(t *testing.T) {
	without := &Commit{Proposals: []*ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: sampleProposal(t, ProposalTypeRemove)},
	}}

	with := &Commit{Proposals: without.Proposals, Path: &tree.UpdatePath{
		LeafNode: sampleLeafNode(),
		Nodes:    []tree.UpdatePathNode{},
	}}

	encode := func(c *Commit) []byte {
		w := mlstls.NewWriter(512)
		if err := c.marshal(w); err != nil {
			t.Fatalf("encoding a commit: %v", err)
		}
		return w.Bytes()
	}

	a, b := encode(without), encode(with)
	if len(b) <= len(a) {
		t.Fatalf("a commit with a path (%d bytes) is not longer than one without (%d), so the "+
			"presence byte is missing or the path is being dropped", len(b), len(a))
	}

	// And the decoder must read both back as they went in.
	for name, original := range map[string]*Commit{"without": without, "with": with} {
		r := mlstls.NewReader(encode(original))
		decoded, err := parseCommit(r)
		if err != nil {
			t.Fatalf("%s: decoding: %v", name, err)
		}
		if (decoded.Path == nil) != (original.Path == nil) {
			t.Fatalf("%s: path presence did not survive (got nil=%v, want nil=%v)",
				name, decoded.Path == nil, original.Path == nil)
		}
	}
}

func TestFramedContentAuthDataDependsOnContentType(t *testing.T) {
	auth := FramedContentAuthData{
		Signature:       bytes.Repeat([]byte{0xF6}, 64),
		ConfirmationTag: bytes.Repeat([]byte{0x77}, 32),
	}

	for _, contentType := range []ContentType{ContentTypeApplication, ContentTypeProposal, ContentTypeCommit} {
		var decoded FramedContentAuthData
		roundTrip(t, "auth", func(w *mlstls.Writer) error {
			return auth.Marshal(w, contentType)
		}, func(r *mlstls.Reader) error {
			a, err := ParseFramedContentAuthData(r, contentType)
			decoded = a
			return err
		})

		switch contentType {
		case ContentTypeCommit:
			if len(decoded.ConfirmationTag) == 0 {
				t.Fatal("a commit's confirmation tag did not survive")
			}
		default:
			if len(decoded.ConfirmationTag) != 0 {
				t.Fatal("a non-commit gained a confirmation tag")
			}
		}
	}

	// The failure that matters: reading a commit's auth data as if it were an application's
	// would leave the confirmation tag in the stream, and every field after it would be
	// misaligned. This asserts the parser refuses rather than silently trailing.
	w := mlstls.NewWriter(128)
	if err := auth.Marshal(w, ContentTypeCommit); err != nil {
		t.Fatal(err)
	}
	reader := mlstls.NewReader(w.Bytes())
	if _, err := ParseFramedContentAuthData(reader, ContentTypeCommit); err != nil {
		t.Fatalf("reading a commit's auth data with its own type failed: %v", err)
	}
	if !reader.Empty() {
		t.Fatal("reading a commit's auth data with its own type left bytes unread")
	}
}

func TestUnknownTypesAndMissingBodiesAreRejected(t *testing.T) {
	// An unknown proposal type must be refused, not treated as an empty proposal.
	w := mlstls.NewWriter(16)
	w.Uint16(0x7fff)
	if _, err := ParseProposal(mlstls.NewReader(w.Bytes())); err == nil {
		t.Fatal("an unknown proposal type was accepted")
	}

	// Add is implemented now that KeyPackage exists, so what is checked here is a missing body
	// rather than a missing feature. The assertion used to require Add to be REFUSED; it was
	// rewritten when the feature landed, and that is the point of a test that names the reason
	// it expects a failure instead of only expecting one.
	if _, err := MarshalProposal(&Proposal{Type: ProposalTypeAdd}); err == nil {
		t.Fatal("an Add proposal with no KeyPackage encoded successfully")
	}
	if _, err := ParseProposal(mlstls.NewReader([]byte{0x00, 0x01})); err == nil {
		t.Fatal("an Add proposal with no bytes after the type decoded successfully")
	}

	// An Update with no leaf node, and a Remove with no index, are refused at encoding.
	if _, err := MarshalProposal(&Proposal{Type: ProposalTypeUpdate}); err == nil {
		t.Fatal("an Update proposal with no leaf node encoded successfully")
	}
	if _, err := MarshalProposal(&Proposal{Type: ProposalTypeRemove}); err == nil {
		t.Fatal("a Remove proposal with no leaf index encoded successfully")
	}

	// A by-reference ProposalOrRef with an empty reference would be indistinguishable from a
	// malformed one; it is refused.
	w2 := mlstls.NewWriter(16)
	if err := (&ProposalOrRef{Type: ProposalOrRefTypeReference}).Marshal(w2); err == nil {
		t.Fatal("an empty proposal reference encoded successfully")
	}

	// Truncated input must produce an error rather than a panic or a partial value.
	full := mlstls.NewWriter(512)
	if err := sampleProposal(t, ProposalTypeUpdate).Marshal(full); err != nil {
		t.Fatal(err)
	}
	encoded := full.Bytes()
	for cut := 1; cut < len(encoded); cut += 7 {
		if _, err := ParseProposal(mlstls.NewReader(encoded[:cut])); err == nil {
			t.Fatalf("a proposal truncated to %d of %d bytes decoded successfully",
				cut, len(encoded))
		}
	}
}

func TestProposalHashDistinguishesProposals(t *testing.T) {
	suite := suiteUnderTest

	a := sampleProposal(t, ProposalTypeRemove)
	b := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 8}}

	hashA, err := a.Hash(suite)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := b.Hash(suite)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(hashA, hashB) {
		t.Fatal("two different proposals hashed to the same value")
	}

	// The same proposal must hash the same way however it was built.
	again, err := sampleProposal(t, ProposalTypeRemove).Hash(suite)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hashA, again) {
		t.Fatal("the same proposal hashed differently on a second construction")
	}
}
