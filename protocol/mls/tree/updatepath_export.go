package tree

import mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"

// MarshalTo encodes an UpdatePath onto an existing writer.
//
// MarshalUpdatePath returns the bytes on their own, which is what a caller wants when the
// path is the whole message. This method exists for the other case: a commit carries the path
// inside an optional field, and writing it through the enclosing writer is what keeps the
// presence byte and the length prefix in the right places. Neither form is redundant — one
// returns bytes, the other continues a stream.
func (u *UpdatePath) MarshalTo(w *mlstls.Writer) error {
	return u.marshal(w)
}
