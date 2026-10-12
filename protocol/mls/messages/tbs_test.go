package messages

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// These tests are the first verification of the signature layer. There are no official
// vectors for FramedContentTBS, so the evidence is the positive case plus the negatives: a
// verification that accepts everything proves nothing.

// testKeyPair derives a deterministic Ed25519 key pair from a label, so a failure is
// reproducible and two different labels never share a key.
func testKeyPair(t *testing.T, label string) (priv, pub []byte) {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	copy(seed, []byte(label))
	key := ed25519.NewKeyFromSeed(seed)
	return key, key.Public().(ed25519.PublicKey)
}

func memberContent(epoch uint64) *FramedContent {
	return &FramedContent{
		GroupID:         []byte("group-1"),
		Epoch:           epoch,
		Sender:          Sender{Type: SenderTypeMember, LeafIndex: 2},
		Type:            ContentTypeApplication,
		ApplicationData: []byte("hello"),
	}
}

func TestFramedContentSignatureRoundTrip(t *testing.T) {
	priv, pub := testKeyPair(t, "member-signature-key")

	groupContext := []byte("encoded group context for epoch 7")
	content := memberContent(7)

	signature, err := SignFramedContent(WireFormatPublicMessage, content, groupContext, priv, suiteUnderTest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if err := VerifyFramedContentSignature(WireFormatPublicMessage, content, groupContext,
		pub, signature, suiteUnderTest); err != nil {
		t.Fatalf("a signature that was just produced did not verify: %v", err)
	}
}

// TestFramedContentSignatureIsBoundToItsContext is the important one: it checks that the
// GroupContext is actually inside the signed bytes. If it were not, a signature made in one
// epoch would verify in every other epoch of the same group — the same content could be
// replayed at a different epoch, and nothing would notice.
func TestFramedContentSignatureIsBoundToItsContext(t *testing.T) {
	priv, pub := testKeyPair(t, "member-signature-key")

	content := memberContent(7)
	original := []byte("group context at epoch 7")
	other := []byte("group context at epoch 8")

	signature, err := SignFramedContent(WireFormatPublicMessage, content, original, priv, suiteUnderTest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if err := VerifyFramedContentSignature(WireFormatPublicMessage, content, other, pub,
		signature, suiteUnderTest); err == nil {
		t.Fatal("a signature made under one group context verified under a different one, so " +
			"the context is not bound into the signed bytes and a message could be replayed " +
			"into another epoch")
	}

	// And a member's content cannot be signed without a context at all.
	if _, err := SignFramedContent(WireFormatPublicMessage, content, nil, priv, suiteUnderTest); err == nil {
		t.Fatal("a member's content was signed with no group context")
	}
}

func TestFramedContentSignatureCoversEverythingItMust(t *testing.T) {
	priv, pub := testKeyPair(t, "member-signature-key")

	content := memberContent(7)
	groupContext := []byte("group context at epoch 7")

	signature, err := SignFramedContent(WireFormatPublicMessage, content, groupContext, priv, suiteUnderTest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Every mutation must break verification. Each one is a field an attacker would want to
	// change without invalidating the signature.
	mutations := map[string]func(*FramedContent){
		"application data": func(c *FramedContent) { c.ApplicationData = []byte("hello!") },
		"epoch":            func(c *FramedContent) { c.Epoch = 8 },
		"group id":         func(c *FramedContent) { c.GroupID = []byte("group-2") },
		"leaf index":       func(c *FramedContent) { c.Sender.LeafIndex = 3 },
		"authenticated data": func(c *FramedContent) {
			c.AuthenticatedData = []byte("extra")
		},
		"sender type":  func(c *FramedContent) { c.Sender.Type = SenderTypeExternal },
		"content type": func(c *FramedContent) { c.Type = ContentTypeProposal },
	}

	for name, mutate := range mutations {
		altered := *content
		mutate(&altered)
		if err := VerifyFramedContentSignature(WireFormatPublicMessage, &altered, groupContext,
			pub, signature, suiteUnderTest); err == nil {
			t.Fatalf("changing the %s did not invalidate the signature, so that field is not "+
				"covered by the signed bytes", name)
		}
	}

	// The wire format is covered as well, which is what stops a message signed for one
	// framing from being presented under another.
	if err := VerifyFramedContentSignature(WireFormatPrivateMessage, content, groupContext,
		pub, signature, suiteUnderTest); err == nil {
		t.Fatal("the same content verified under a different wire format")
	}

	// And a different key must not verify.
	_, otherPub := testKeyPair(t, "another-signature-key")
	if err := VerifyFramedContentSignature(WireFormatPublicMessage, content, groupContext,
		otherPub, signature, suiteUnderTest); err == nil {
		t.Fatal("a signature verified under a different public key")
	}

	// A tampered signature must not verify.
	broken := append([]byte(nil), signature...)
	broken[0] ^= 0x01
	if err := VerifyFramedContentSignature(WireFormatPublicMessage, content, groupContext,
		pub, broken, suiteUnderTest); err == nil {
		t.Fatal("a signature with a flipped bit verified")
	}

	if err := VerifyFramedContentSignature(WireFormatPublicMessage, content, groupContext,
		pub, nil, suiteUnderTest); err == nil {
		t.Fatal("an empty signature verified")
	}
}

// TestExternalSendersAreNotBoundToTheContext pins the asymmetry the specification draws: a
// member's TBS carries the group context and an external sender's does not. An implementation
// that bound it for everyone, or for no one, would still be self-consistent — and would
// disagree with every other implementation.
func TestExternalSendersAreNotBoundToTheContext(t *testing.T) {
	external := &FramedContent{
		GroupID:         []byte("group-1"),
		Epoch:           0,
		Sender:          Sender{Type: SenderTypeExternal, SenderIndex: 1},
		Type:            ContentTypeApplication,
		ApplicationData: []byte("from outside"),
	}

	withoutContext, err := FramedContentTBS(WireFormatPublicMessage, external, nil)
	if err != nil {
		t.Fatalf("an external sender's TBS required a group context: %v", err)
	}

	// Supplying one must make no difference: it is not part of the encoding.
	withContext, err := FramedContentTBS(WireFormatPublicMessage, external, []byte("ignored"))
	if err != nil {
		t.Fatalf("building the TBS with a context failed: %v", err)
	}
	if !bytes.Equal(withoutContext, withContext) {
		t.Fatal("the group context changed an external sender's signed bytes, so the " +
			"asymmetry between member and external senders is not being honoured")
	}

	// Whereas a member's TBS must differ once the context differs.
	member := memberContent(0)
	a, err := FramedContentTBS(WireFormatPublicMessage, member, []byte("context A"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := FramedContentTBS(WireFormatPublicMessage, member, []byte("context B"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two different group contexts produced the same signed bytes for a member")
	}
}

func TestAuthenticatedContentVerificationUsesTheEnclosedContent(t *testing.T) {
	priv, pub := testKeyPair(t, "member-signature-key")

	groupContext := []byte("group context")

	ac := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    *memberContent(3),
	}
	signature, err := SignFramedContent(ac.WireFormat, &ac.Content, groupContext, priv, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	ac.Auth.Signature = signature

	if err := VerifyAuthenticatedContent(ac, groupContext, pub, suiteUnderTest); err != nil {
		t.Fatalf("verifying an authenticated content: %v", err)
	}

	ac.Content.Epoch = 4
	if err := VerifyAuthenticatedContent(ac, groupContext, pub, suiteUnderTest); err == nil {
		t.Fatal("an altered authenticated content verified")
	}
}
