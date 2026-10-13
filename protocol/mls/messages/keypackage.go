package messages

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// KeyPackages (RFC 9420 section 10), the structure an Add proposal carries.
//
//	struct {
//	    ProtocolVersion version;
//	    CipherSuite cipher_suite;
//	    HPKEPublicKey init_key;
//	    LeafNode leaf_node;
//	    Extension extensions<V>;
//	    /* SignWithLabel(., "KeyPackageTBS", KeyPackageTBS) */
//	    opaque signature<V>;
//	} KeyPackage;
//
//	struct {
//	    ProtocolVersion version;
//	    CipherSuite cipher_suite;
//	    HPKEPublicKey init_key;
//	    LeafNode leaf_node;
//	    Extension extensions<V>;
//	} KeyPackageTBS;
//
// # What each field is for, because the names do not say
//
//   - init_key is the public key a Welcome is encrypted to, so that a member can be added
//     while offline. It is NOT the leaf's encryption key and the two must differ: the leaf key
//     protects the member inside the group, the init key protects the message that lets it in.
//     Reusing one for the other would tie the group's forward secrecy to a key that has
//     already been used outside it.
//
//   - leaf_node is the member's appearance in the tree, and it carries its OWN signature. A
//     KeyPackage is therefore signed twice over: the leaf signs itself, and the KeyPackage
//     signature covers the leaf.
//
//   - A KeyPackage is used ONCE. Reuse is allowed only as a last resort, which is why the
//     reference below exists: it identifies a specific published package, not a client.
//
// # Validation, which is not the same as parsing
//
// A well-formed KeyPackage can still be one that must be refused, and the specification lists
// the checks (section 10.1): the version and ciphersuite must match the group's, the leaf must
// be valid for a key package, the signature must verify under the key in the leaf's
// credential, and the leaf's encryption key must differ from the init key. VerifyKeyPackage
// performs them; Parse does not, because a structure that refuses to parse cannot be examined
// when something is wrong with it.

// KeyPackage is a pre-published invitation to join a group.
type KeyPackage struct {
	Version     uint16
	CipherSuite uint16
	InitKey     []byte
	LeafNode    *tree.LeafNode
	Extensions  []tree.Extension
	Signature   []byte
}

// KeyPackageRef identifies one published KeyPackage.
//
// MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value) — a labelled hash,
// like a proposal reference, and not a MAC.
type KeyPackageRef []byte

// KeyPackageTBSBytes builds the bytes a KeyPackage's signature covers: every field except the
// signature itself.
func (k *KeyPackage) KeyPackageTBSBytes() ([]byte, error) {
	if k.LeafNode == nil {
		return nil, fmt.Errorf("mls/messages: a KeyPackage needs a leaf node")
	}

	w := mlstls.NewWriter(256)
	w.Uint16(k.Version)
	w.Uint16(k.CipherSuite)
	w.Opaque(k.InitKey)
	if err := k.LeafNode.MarshalTo(w); err != nil {
		return nil, err
	}
	writeExtensionsOf(w, k.Extensions)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// SignKeyPackage signs the package with the member's signature key.
//
// The suite parameter is used only to reject a suite whose signature scheme is not Ed25519:
// the signing helper takes no suite, because Ed25519 does not need one, so a suite expecting
// ECDSA would otherwise be silently signed with the wrong scheme — succeeding locally and
// rejected by everyone else.
func SignKeyPackage(k *KeyPackage, signatureKey []byte, suite crypto.CipherSuite) ([]byte, error) {
	if err := requireEd25519(suite); err != nil {
		return nil, err
	}

	tbs, err := k.KeyPackageTBSBytes()
	if err != nil {
		return nil, err
	}
	return crypto.SignWithLabel(signatureKey, "KeyPackageTBS", tbs)
}

// VerifyKeyPackage checks a KeyPackage against the group it is being added to.
//
// groupVersion and groupCipherSuite are the values from the GroupContext: a package for another
// version or another ciphersuite describes a group this one is not, and accepting it would put
// a member in the tree whose keys nothing else in the group can use.
func VerifyKeyPackage(k *KeyPackage, groupVersion, groupCipherSuite uint16, suite crypto.CipherSuite) error {
	if k == nil {
		return fmt.Errorf("mls/messages: no KeyPackage")
	}
	if k.Version != groupVersion {
		return fmt.Errorf("mls/messages: the KeyPackage is for protocol version %d and the group "+
			"is %d", k.Version, groupVersion)
	}
	if k.CipherSuite != groupCipherSuite {
		return fmt.Errorf("mls/messages: the KeyPackage is for cipher suite %#04x and the group "+
			"is %#04x", k.CipherSuite, groupCipherSuite)
	}
	if k.LeafNode == nil {
		return fmt.Errorf("mls/messages: the KeyPackage has no leaf node")
	}
	if len(k.InitKey) == 0 {
		return fmt.Errorf("mls/messages: the KeyPackage has no init key")
	}

	// The init key and the leaf's encryption key must differ. Sharing one would mean the key
	// that protects the Welcome is also the key that protects the member's traffic, so a
	// compromise of either reaches both.
	if string(k.InitKey) == string(k.LeafNode.EncryptionKey) {
		return fmt.Errorf("mls/messages: the KeyPackage reuses its leaf encryption key as its init " +
			"key; the two protect different things and must differ")
	}

	tbs, err := k.KeyPackageTBSBytes()
	if err != nil {
		return err
	}
	if len(k.Signature) == 0 {
		return fmt.Errorf("mls/messages: the KeyPackage is unsigned")
	}
	if err := crypto.VerifyWithLabel(k.LeafNode.SignatureKey, "KeyPackageTBS", tbs, k.Signature); err != nil {
		return fmt.Errorf("mls/messages: the KeyPackage signature does not verify: %w", err)
	}

	return nil
}

// MakeKeyPackageReference computes the reference for a published KeyPackage.
func MakeKeyPackageReference(k *KeyPackage, suite crypto.CipherSuite) (KeyPackageRef, error) {
	encoded, err := MarshalKeyPackage(k)
	if err != nil {
		return nil, err
	}
	digest, err := crypto.RefHash("MLS 1.0 KeyPackage Reference", encoded, suite)
	if err != nil {
		return nil, err
	}
	return KeyPackageRef(digest), nil
}

// ParseKeyPackage decodes a KeyPackage.
func ParseKeyPackage(r *mlstls.Reader) (*KeyPackage, error) {
	out := &KeyPackage{}

	var err error
	if out.Version, err = r.Uint16(); err != nil {
		return nil, err
	}
	if out.CipherSuite, err = r.Uint16(); err != nil {
		return nil, err
	}
	if out.InitKey, err = r.Opaque(); err != nil {
		return nil, err
	}

	leaf, err := tree.ParseLeafNode(r)
	if err != nil {
		return nil, err
	}
	out.LeafNode = leaf

	if out.Extensions, err = parseExtensionsOf(r); err != nil {
		return nil, err
	}
	if out.Signature, err = r.Opaque(); err != nil {
		return nil, err
	}
	return out, nil
}

// Marshal writes a KeyPackage.
func (k *KeyPackage) Marshal(w *mlstls.Writer) error {
	if k.LeafNode == nil {
		return fmt.Errorf("mls/messages: a KeyPackage needs a leaf node")
	}

	w.Uint16(k.Version)
	w.Uint16(k.CipherSuite)
	w.Opaque(k.InitKey)
	if err := k.LeafNode.MarshalTo(w); err != nil {
		return err
	}
	writeExtensionsOf(w, k.Extensions)
	w.Opaque(k.Signature)
	return nil
}

// MarshalKeyPackage encodes a KeyPackage and returns the bytes.
func MarshalKeyPackage(k *KeyPackage) ([]byte, error) {
	w := mlstls.NewWriter(512)
	if err := k.Marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
