package schedule

import (
	"fmt"

	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// Parsing a GroupContext.
//
// The encoding is written from the same field order that Marshal produces and that the official
// key-schedule vectors confirm byte for byte: version, cipher suite, group id, EPOCH, tree
// hash, confirmed transcript hash, extensions. The epoch's position between the group id and
// the two hashes is the part that is easy to misread, and getting it wrong shifts every
// following field.
//
// A parser lives here rather than beside each caller because this package owns the structure: a
// second parser elsewhere would be a second chance to disagree about the order.

// ParseGroupContext decodes a GroupContext.
func ParseGroupContext(r *mlstls.Reader) (GroupContext, error) {
	var out GroupContext
	var err error

	if out.Version, err = r.Uint16(); err != nil {
		return out, err
	}
	if out.CipherSuite, err = r.Uint16(); err != nil {
		return out, err
	}
	if out.GroupID, err = r.Opaque(); err != nil {
		return out, err
	}
	if out.Epoch, err = r.Uint64(); err != nil {
		return out, err
	}
	if out.TreeHash, err = r.Opaque(); err != nil {
		return out, err
	}
	if out.ConfirmedTranscriptHash, err = r.Opaque(); err != nil {
		return out, err
	}
	if out.Extensions, err = r.Opaque(); err != nil {
		return out, err
	}

	// The extension vector is kept as the encoded body, which is what Marshal expects to write
	// back. A caller that wants the extensions themselves decodes them from here.
	return out, nil
}

// ParseGroupContextBytes decodes a GroupContext from a complete byte slice.
//
// It refuses trailing bytes rather than ignoring them: a context with something appended is
// either a misreading of where it ends or a structure this package does not know, and silently
// accepting it would let two members hash different bytes under the same name.
func ParseGroupContextBytes(encoded []byte) (GroupContext, error) {
	r := mlstls.NewReader(encoded)
	out, err := ParseGroupContext(r)
	if err != nil {
		return GroupContext{}, err
	}
	if !r.Empty() {
		return GroupContext{}, fmt.Errorf("mls/schedule: %d bytes follow the group context", len(encoded))
	}
	return out, nil
}
