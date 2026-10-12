package messages

import (
	mlstls "github.com/schat/schat/protocol/mls/tls"
	"github.com/schat/schat/protocol/mls/tree"
)

// Extension vectors, encoded locally.
//
// The tree package has the same two helpers unexported, because a LeafNode carries extensions
// and that package owns the LeafNode encoding. A KeyPackage carries its own extension vector
// at the top level, so this package needs the same shape — and duplicating four lines here is
// a smaller cost than widening the tree package's public surface for a structure it does not
// itself need to encode.
//
// The two MUST stay in step: the extension vector is `Extension extensions<V>` where
//
//	struct { ExtensionType extension_type; opaque extension_data<V>; } Extension;
//
// and ExtensionType is two bytes. Encoding it as one would misalign every field after it.

func parseExtensionsOf(r *mlstls.Reader) ([]tree.Extension, error) {
	var out []tree.Extension
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
			out = append(out, tree.Extension{Type: rawType, Data: data})
		}
		return nil
	})
	return out, err
}

func writeExtensionsOf(w *mlstls.Writer, extensions []tree.Extension) {
	w.Vector(func(w *mlstls.Writer) error {
		for _, e := range extensions {
			w.Uint16(e.Type)
			w.Opaque(e.Data)
		}
		return nil
	})
}
