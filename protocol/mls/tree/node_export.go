package tree

import mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"

// Exported entry points to this package's codecs.
//
// The marshalling and parsing functions are unexported because within the package they are
// spelled tersely and used constantly; other packages still need to encode a LeafNode — a
// proposal carries one, a KeyPackage wraps one — so the wrappers below exist rather than
// renaming the originals and touching code that the vectors already verify.
//
// Keeping them here, in a file of their own, is deliberate: it is the complete list of what
// the rest of the project may call, so a reader can see the package's public surface in one
// place instead of inferring it from a mix of files.

// ParseLeafNode decodes a LeafNode from a reader positioned at its start.
func ParseLeafNode(r *mlstls.Reader) (*LeafNode, error) {
	return parseLeafNode(r)
}

// MarshalTo encodes a LeafNode onto a writer.
func (l *LeafNode) MarshalTo(w *mlstls.Writer) error {
	return l.marshal(w)
}

// MarshalLeafNode encodes a LeafNode and returns the bytes.
func MarshalLeafNode(l *LeafNode) ([]byte, error) {
	w := mlstls.NewWriter(256)
	if err := l.marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
