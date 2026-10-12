// Package tree's node codec: the wire format of a ratchet tree (RFC 9420 section 7.1-7.2).
//
// # How this file was written
//
// Not from memory. The field order and the widths of the enums were read off the
// specification text and then confirmed by hand-parsing the first entry of the official
// tree-validation vector down to the last byte. That mattered: an earlier attempt from
// memory mis-split the Capabilities struct, which produced an odd byte length for a vector
// of uint16 values — impossible, and a signal that the remembered layout was wrong.
//
// Two rules from the specification are easy to miss and both were needed to parse the
// vector at all:
//
//   - Capabilities lists only NON-DEFAULT proposal and extension types. add, update,
//     remove, psk, reinit, external_init and group_context_extensions MUST NOT appear, so
//     an empty proposals vector is the normal case rather than a sign of truncation.
//
//   - NodeType and LeafNodeSource are one byte (their enums end at (255)), while
//     CredentialType, ExtensionType, ProtocolVersion and CipherSuite are two bytes.
//
// # What is verified, and what is not
//
// The round trip in vectors_test.go covers everything the official trees contain. The x509
// credential branch is REFUSED rather than guessed: no vector in this repository exercises
// it, SCHAT's design uses basic credentials, and a branch that has never been run is a
// branch whose correctness is unknown. Refusing it produces a clear error instead of
// silently mis-parsing a message from an implementation that uses x509.
package tree

import (
	"encoding/binary"
	"fmt"

	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// NodeType identifies what a node holds. A one-byte enum: its values end at (255).
type NodeType uint8

const (
	NodeTypeReserved NodeType = 0
	NodeTypeLeaf     NodeType = 1
	NodeTypeParent   NodeType = 2
)

// LeafNodeSource says how a leaf came to be in the tree. One byte.
//
// It decides which extra fields the leaf carries and, later, whether the signature is
// bound to a group id — a KeyPackage is signed before its group exists, so it cannot be.
type LeafNodeSource uint8

const (
	LeafNodeSourceReserved   LeafNodeSource = 0
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

// CredentialType is a two-byte enum.
type CredentialType uint16

const (
	CredentialTypeBasic CredentialType = 1
	CredentialTypeX509  CredentialType = 2
)

// ErrUnsupportedCredential means the credential type is one this package refuses to guess
// at; see the package comment.
var ErrUnsupportedCredential = fmt.Errorf("mls/tree: unsupported credential type")

// Credential identifies a member. Only the basic form is implemented.
type Credential struct {
	Type     CredentialType
	Identity []byte
}

// Capabilities is what a member claims to support.
//
// The lists hold raw values rather than named constants: unknown values MUST be ignored
// (that is what GREASE depends on), so decoding one has to succeed even when this package
// has never heard of it.
type Capabilities struct {
	Versions     []uint16
	CipherSuites []uint16
	Extensions   []uint16
	Proposals    []uint16
	Credentials  []uint16
}

// Lifetime is when a KeyPackage's leaf is valid, in seconds since the Unix epoch.
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// Extension is one typed extension.
type Extension struct {
	Type uint16
	Data []byte
}

// LeafNode is a member's appearance in the tree.
type LeafNode struct {
	EncryptionKey []byte
	SignatureKey  []byte
	Credential    Credential
	Capabilities  Capabilities
	Source        LeafNodeSource

	// Lifetime is present only when Source is key_package.
	Lifetime *Lifetime

	// ParentHash is present only when Source is commit.
	ParentHash []byte

	Extensions []Extension
	Signature  []byte
}

// ParentNode is a subtree's public key and the bookkeeping around it.
type ParentNode struct {
	EncryptionKey []byte
	ParentHash    []byte

	// UnmergedLeaves lists, in increasing order, the leaves below this node that have not
	// been merged into its subtree. The ordering is a MUST in the specification, and it is
	// what makes the list unambiguous without a set type.
	UnmergedLeaves []uint32
}

// Node is one entry of the tree: either a leaf, a parent, or absent.
type Node struct {
	Type   NodeType
	Leaf   *LeafNode
	Parent *ParentNode
}

// Tree is the ratchet tree. A nil element is a blank node.
//
// The array layout is the one in the tree package: 2n-1 entries, leaves at even indices,
// the root at n-1.
type Tree []*Node

// ParseTree decodes `optional<Node> ratchet_tree<V>`.
func ParseTree(r *mlstls.Reader) (Tree, error) {
	var out Tree
	err := r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			var node *Node
			present, err := r.Optional(func(r *mlstls.Reader) error {
				parsed, err := parseNode(r)
				if err != nil {
					return err
				}
				node = parsed
				return nil
			})
			if err != nil {
				return err
			}
			if !present {
				node = nil
			}
			out = append(out, node)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalTree encodes a tree in the same form, including the outer vector length.
//
// The round trip against the official vectors is the only evidence that this is right, and
// it is deliberately exact: a tree that re-encodes to different bytes would produce a
// different tree hash, and therefore a different epoch secret, from the same contents.
func MarshalTree(t Tree) ([]byte, error) {
	w := mlstls.NewWriter(64 * len(t))
	w.Vector(func(w *mlstls.Writer) error {
		for _, node := range t {
			if node == nil {
				w.Optional(nil)
				continue
			}
			n := node
			w.Optional(func(w *mlstls.Writer) error { return n.marshal(w) })
		}
		return nil
	})
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func parseNode(r *mlstls.Reader) (*Node, error) {
	rawType, err := r.Uint8()
	if err != nil {
		return nil, err
	}
	nodeType := NodeType(rawType)

	switch nodeType {
	case NodeTypeLeaf:
		leaf, err := parseLeafNode(r)
		if err != nil {
			return nil, err
		}
		return &Node{Type: nodeType, Leaf: leaf}, nil

	case NodeTypeParent:
		parent, err := parseParentNode(r)
		if err != nil {
			return nil, err
		}
		return &Node{Type: nodeType, Parent: parent}, nil

	default:
		return nil, fmt.Errorf("mls/tree: unknown node type %d", rawType)
	}
}

func (n *Node) marshal(w *mlstls.Writer) error {
	w.Uint8(uint8(n.Type))
	switch n.Type {
	case NodeTypeLeaf:
		if n.Leaf == nil {
			return fmt.Errorf("mls/tree: leaf node has no leaf content")
		}
		return n.Leaf.marshal(w)
	case NodeTypeParent:
		if n.Parent == nil {
			return fmt.Errorf("mls/tree: parent node has no parent content")
		}
		return n.Parent.marshal(w)
	default:
		return fmt.Errorf("mls/tree: unknown node type %d", n.Type)
	}
}

func parseLeafNode(r *mlstls.Reader) (*LeafNode, error) {
	leaf := &LeafNode{}
	var err error

	if leaf.EncryptionKey, err = r.Opaque(); err != nil {
		return nil, err
	}
	if leaf.SignatureKey, err = r.Opaque(); err != nil {
		return nil, err
	}

	credential, err := parseCredential(r)
	if err != nil {
		return nil, err
	}
	leaf.Credential = credential

	if leaf.Capabilities, err = parseCapabilities(r); err != nil {
		return nil, err
	}

	rawSource, err := r.Uint8()
	if err != nil {
		return nil, err
	}
	leaf.Source = LeafNodeSource(rawSource)

	switch leaf.Source {
	case LeafNodeSourceKeyPackage:
		before, err := r.Uint64()
		if err != nil {
			return nil, err
		}
		after, err := r.Uint64()
		if err != nil {
			return nil, err
		}
		leaf.Lifetime = &Lifetime{NotBefore: before, NotAfter: after}

	case LeafNodeSourceUpdate:
		// An empty struct on the wire: nothing to read.

	case LeafNodeSourceCommit:
		if leaf.ParentHash, err = r.Opaque(); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("mls/tree: unknown leaf node source %d", rawSource)
	}

	if leaf.Extensions, err = parseExtensions(r); err != nil {
		return nil, err
	}
	if leaf.Signature, err = r.Opaque(); err != nil {
		return nil, err
	}
	return leaf, nil
}

func (l *LeafNode) marshal(w *mlstls.Writer) error {
	w.Opaque(l.EncryptionKey)
	w.Opaque(l.SignatureKey)
	l.Credential.marshal(w)
	l.Capabilities.marshal(w)
	w.Uint8(uint8(l.Source))

	switch l.Source {
	case LeafNodeSourceKeyPackage:
		if l.Lifetime == nil {
			return fmt.Errorf("mls/tree: a key_package leaf must carry a lifetime")
		}
		w.Uint64(l.Lifetime.NotBefore)
		w.Uint64(l.Lifetime.NotAfter)
	case LeafNodeSourceUpdate:
	case LeafNodeSourceCommit:
		w.Opaque(l.ParentHash)
	default:
		return fmt.Errorf("mls/tree: unknown leaf node source %d", l.Source)
	}

	marshalExtensions(w, l.Extensions)
	w.Opaque(l.Signature)
	return nil
}

func parseCredential(r *mlstls.Reader) (Credential, error) {
	rawType, err := r.Uint16()
	if err != nil {
		return Credential{}, err
	}

	switch CredentialType(rawType) {
	case CredentialTypeBasic:
		identity, err := r.Opaque()
		if err != nil {
			return Credential{}, err
		}
		return Credential{Type: CredentialTypeBasic, Identity: identity}, nil

	case CredentialTypeX509:
		// Refused on purpose: see the package comment. Parsing it anyway would mean
		// shipping a branch no vector has ever run.
		return Credential{}, fmt.Errorf("%w: x509 (%d)", ErrUnsupportedCredential, rawType)

	default:
		return Credential{}, fmt.Errorf("%w: %d", ErrUnsupportedCredential, rawType)
	}
}

func (c Credential) marshal(w *mlstls.Writer) {
	w.Uint16(uint16(c.Type))
	switch c.Type {
	case CredentialTypeBasic:
		w.Opaque(c.Identity)
	}
}

func parseCapabilities(r *mlstls.Reader) (Capabilities, error) {
	var caps Capabilities
	var err error

	if caps.Versions, err = readUint16Vector(r); err != nil {
		return caps, err
	}
	if caps.CipherSuites, err = readUint16Vector(r); err != nil {
		return caps, err
	}
	if caps.Extensions, err = readUint16Vector(r); err != nil {
		return caps, err
	}
	if caps.Proposals, err = readUint16Vector(r); err != nil {
		return caps, err
	}
	if caps.Credentials, err = readUint16Vector(r); err != nil {
		return caps, err
	}
	return caps, nil
}

func (c Capabilities) marshal(w *mlstls.Writer) {
	writeUint16Vector(w, c.Versions)
	writeUint16Vector(w, c.CipherSuites)
	writeUint16Vector(w, c.Extensions)
	writeUint16Vector(w, c.Proposals)
	writeUint16Vector(w, c.Credentials)
}

func readUint16Vector(r *mlstls.Reader) ([]uint16, error) {
	var out []uint16
	err := r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			v, err := r.Uint16()
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}

func writeUint16Vector(w *mlstls.Writer, values []uint16) {
	w.Vector(func(w *mlstls.Writer) error {
		for _, v := range values {
			w.Uint16(v)
		}
		return nil
	})
}

func parseExtensions(r *mlstls.Reader) ([]Extension, error) {
	var out []Extension
	err := r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			rawType, err := r.Uint16()
			if err != nil {
				return err
			}
			data, err := r.Opaque()
			if err != nil {
				return err
			}
			out = append(out, Extension{Type: rawType, Data: data})
		}
		return nil
	})
	return out, err
}

func marshalExtensions(w *mlstls.Writer, extensions []Extension) {
	w.Vector(func(w *mlstls.Writer) error {
		for _, e := range extensions {
			w.Uint16(e.Type)
			w.Opaque(e.Data)
		}
		return nil
	})
}

func parseParentNode(r *mlstls.Reader) (*ParentNode, error) {
	parent := &ParentNode{}

	var err error
	if parent.EncryptionKey, err = r.Opaque(); err != nil {
		return nil, err
	}
	if parent.ParentHash, err = r.Opaque(); err != nil {
		return nil, err
	}

	// `uint32 unmerged_leaves<V>`: the vector length is in BYTES, four per entry.
	err = r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			raw, err := r.Raw(4)
			if err != nil {
				return err
			}
			parent.UnmergedLeaves = append(parent.UnmergedLeaves, binary.BigEndian.Uint32(raw))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return parent, nil
}

func (p *ParentNode) marshal(w *mlstls.Writer) error {
	w.Opaque(p.EncryptionKey)
	w.Opaque(p.ParentHash)
	w.Vector(func(w *mlstls.Writer) error {
		var buf [4]byte
		for _, leaf := range p.UnmergedLeaves {
			binary.BigEndian.PutUint32(buf[:], leaf)
			w.Raw(buf[:])
		}
		return nil
	})
	return nil
}
