package messages

import (
	"fmt"

	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// The safe entry point for reading a whole authenticated message.
//
// # The hazard this exists to remove
//
// FramedContentAuthData's layout depends on the content type: a commit carries a
// confirmation tag and the other types do not. The type is NOT part of the auth data — it
// lives in the FramedContent that precedes it — so a caller that passes the wrong type gets a
// parse that SUCCEEDS and silently leaves the confirmation tag unread.
//
// That is not a hypothetical inconvenience. The confirmation tag is the MAC that proves a
// member computed the same epoch as everyone else; a commit whose tag is skipped is a commit
// whose epoch agreement was never checked. Making the wrong type impossible to pass is worth
// more than documenting that it is wrong to pass it.
//
// These two functions therefore read and write the content and its authentication together,
// taking the type from the content itself.

// ParseAuthenticatedContent decodes a WireFormat, a FramedContent and that content's
// authentication, in that order, using the content's own type for the authentication layout.
//
// The signature is NOT verified here: verification needs the sender's signature key and, for
// members, the epoch's GroupContext, neither of which is part of these bytes. A caller that
// treats the result as authenticated without verifying it has skipped the only step that
// makes it so.
func ParseAuthenticatedContent(r *mlstls.Reader) (*AuthenticatedContent, error) {
	rawFormat, err := r.Uint16()
	if err != nil {
		return nil, err
	}

	content, err := ParseFramedContent(r)
	if err != nil {
		return nil, err
	}

	auth, err := ParseFramedContentAuthData(r, content.Type)
	if err != nil {
		return nil, err
	}

	return &AuthenticatedContent{
		WireFormat: WireFormat(rawFormat),
		Content:    *content,
		Auth:       auth,
	}, nil
}

// Marshal encodes a wire format, its content and that content's authentication.
func (a *AuthenticatedContent) Marshal(w *mlstls.Writer) error {
	if a.WireFormat == 0 {
		return fmt.Errorf("mls/messages: an authenticated content with no wire format")
	}

	w.Uint16(uint16(a.WireFormat))
	if err := a.Content.Marshal(w); err != nil {
		return err
	}
	return a.Auth.Marshal(w, a.Content.Type)
}
