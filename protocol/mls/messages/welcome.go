package messages

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// Welcome messages (RFC 9420 section 12.4.3.1).
//
//	struct {
//	    CipherSuite cipher_suite;
//	    EncryptedGroupSecrets secrets<V>;
//	    opaque encrypted_group_info<V>;
//	} Welcome;
//
//	struct {
//	    KeyPackageRef new_member;
//	    HPKECiphertext encrypted_group_secrets;
//	} EncryptedGroupSecrets;
//
//	struct {
//	    opaque joiner_secret<V>;
//	    optional<PathSecret> path_secret;
//	    PreSharedKeyID psks<V>;
//	} GroupSecrets;
//
//	struct { opaque path_secret<V>; } PathSecret;
//
// # The encryption context is the odd part, and the part that must not be guessed
//
//	encrypted_group_secrets = EncryptWithLabel(init_key, "Welcome",
//	                                           encrypted_group_info, group_secrets)
//
// The HPKE context is the ENCRYPTED GROUP INFO — the ciphertext of the GroupInfo, not the
// group context and not the empty string. It binds the group secrets to that one GroupInfo, so
// the secrets out of one Welcome cannot be recombined with the GroupInfo of another.
//
// An implementation that used an empty context would work perfectly against itself, because it
// would decrypt what it encrypted, and would agree with nobody else. This comment exists
// because the empty context is what a reader expects and what the specification does not say.
//
// # Where the new member's secrets come from
//
// joiner_secret is the one the key schedule produces — the value this project already verifies
// against the official key-schedule vectors. path_secret is the path secret of the LOWEST node
// on the direct paths of both the committer and the new member, and it is what lets the new
// member compute the private keys for the nodes above its own leaf that the commit reset.

// PSKType is a one-byte enum: its values end at (255).
type PSKType uint8

const (
	PSKTypeReserved   PSKType = 0
	PSKTypeExternal   PSKType = 1
	PSKTypeResumption PSKType = 2
)

// ResumptionPSKUsage is a one-byte enum.
type ResumptionPSKUsage uint8

const (
	ResumptionPSKUsageReserved    ResumptionPSKUsage = 0
	ResumptionPSKUsageApplication ResumptionPSKUsage = 1
	ResumptionPSKUsageReinit      ResumptionPSKUsage = 2
	ResumptionPSKUsageBranch      ResumptionPSKUsage = 3
)

// PreSharedKeyID names a PSK without carrying it.
type PreSharedKeyID struct {
	Type PSKType

	// ID is the opaque identifier of an external PSK.
	ID []byte

	// Usage, GroupID and Epoch identify a resumption PSK: the group it came from and the epoch
	// whose resumption_psk it is.
	Usage   ResumptionPSKUsage
	GroupID []byte
	Epoch   uint64

	// Nonce is fresh randomness of the hash length. It is what makes the same PSK produce a
	// different input each time it is injected, so it is required rather than optional.
	Nonce []byte
}

// PathSecret is one path secret delivered to a new member.
type PathSecret struct {
	PathSecret []byte
}

// GroupSecrets is what a Welcome actually delivers, encrypted.
type GroupSecrets struct {
	JoinerSecret []byte

	// PathSecret is optional: a commit that adds a member without an update path has none to
	// deliver, and a zero-length value must not be confused with an absent one.
	PathSecret *PathSecret

	PSKs []PreSharedKeyID
}

// EncryptedGroupSecrets is one new member's copy of the group secrets.
type EncryptedGroupSecrets struct {
	NewMember             KeyPackageRef
	EncryptedGroupSecrets HPKECiphertext
}

// HPKECiphertext is one HPKE ciphertext: a KEM output and a payload.
type HPKECiphertext struct {
	KemOutput  []byte
	Ciphertext []byte
}

// Welcome is the message that lets a new member join.
type Welcome struct {
	CipherSuite uint16

	// Secrets holds one entry per new member, each encrypted to that member's init key.
	Secrets []EncryptedGroupSecrets

	// EncryptedGroupInfo is the GroupInfo for the new epoch, encrypted under a key derived from
	// the joiner secret. It also serves as the HPKE context for every entry of Secrets, which is
	// why it must be built before them.
	EncryptedGroupInfo []byte
}

// MarshalGroupSecrets encodes the secrets a Welcome delivers.
func MarshalGroupSecrets(s *GroupSecrets) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("mls/messages: no group secrets")
	}

	w := mlstls.NewWriter(256)
	w.Opaque(s.JoinerSecret)

	if s.PathSecret == nil {
		w.Optional(nil)
	} else {
		secret := s.PathSecret.PathSecret
		w.Optional(func(w *mlstls.Writer) error {
			w.Opaque(secret)
			return nil
		})
	}

	writePSKIDs(w, s.PSKs)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// ParseGroupSecrets decodes the secrets a Welcome delivers.
func ParseGroupSecrets(r *mlstls.Reader) (*GroupSecrets, error) {
	out := &GroupSecrets{}

	var err error
	if out.JoinerSecret, err = r.Opaque(); err != nil {
		return nil, err
	}

	present, err := r.Optional(func(r *mlstls.Reader) error {
		secret, err := r.Opaque()
		if err != nil {
			return err
		}
		out.PathSecret = &PathSecret{PathSecret: secret}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !present {
		out.PathSecret = nil
	}

	if out.PSKs, err = parsePSKIDs(r); err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptGroupSecrets seals one member's group secrets to its init key.
//
// encryptedGroupInfo is the CONTEXT as well as being passed in: the specification uses the
// ciphertext of the GroupInfo as the HPKE context, which is what ties these secrets to that
// GroupInfo and to no other. A caller therefore has to build the GroupInfo first — the order is
// forced, not a matter of convenience.
func EncryptGroupSecrets(
	initKey []byte,
	encryptedGroupInfo []byte,
	secrets *GroupSecrets,
	suite crypto.CipherSuite,
) (HPKECiphertext, error) {
	if len(initKey) == 0 {
		return HPKECiphertext{}, fmt.Errorf("mls/messages: no init key to encrypt to")
	}
	if len(encryptedGroupInfo) == 0 {
		return HPKECiphertext{}, fmt.Errorf("mls/messages: no encrypted group info to bind the " +
			"secrets to; the specification uses it as the HPKE context, so it cannot be omitted")
	}

	plaintext, err := MarshalGroupSecrets(secrets)
	if err != nil {
		return HPKECiphertext{}, err
	}

	kemOutput, ciphertext, err := crypto.EncryptWithLabel(initKey, "Welcome", encryptedGroupInfo,
		plaintext, suite)
	if err != nil {
		return HPKECiphertext{}, err
	}
	return HPKECiphertext{KemOutput: kemOutput, Ciphertext: ciphertext}, nil
}

// DecryptGroupSecrets opens a member's copy of the group secrets.
//
// The same encryptedGroupInfo must be supplied as was used to seal it. A member that passes
// anything else — an empty context, or the GroupInfo of another epoch — gets a decryption
// failure that says nothing about which of the two was wrong, which is exactly why the context
// is threaded through here rather than defaulted.
func DecryptGroupSecrets(
	initKeyPrivate []byte,
	encryptedGroupInfo []byte,
	sealed HPKECiphertext,
	suite crypto.CipherSuite,
) (*GroupSecrets, error) {
	plaintext, err := crypto.DecryptWithLabel(initKeyPrivate, "Welcome", encryptedGroupInfo,
		sealed.KemOutput, sealed.Ciphertext, suite)
	if err != nil {
		return nil, fmt.Errorf("mls/messages: opening the group secrets: %w", err)
	}
	return ParseGroupSecrets(mlstls.NewReader(plaintext))
}

// ParseWelcome decodes a Welcome.
func ParseWelcome(r *mlstls.Reader) (*Welcome, error) {
	out := &Welcome{}

	var err error
	if out.CipherSuite, err = r.Uint16(); err != nil {
		return nil, err
	}

	if err := r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			var entry EncryptedGroupSecrets

			ref, err := r.Opaque()
			if err != nil {
				return err
			}
			entry.NewMember = KeyPackageRef(ref)

			if entry.EncryptedGroupSecrets.KemOutput, err = r.Opaque(); err != nil {
				return err
			}
			if entry.EncryptedGroupSecrets.Ciphertext, err = r.Opaque(); err != nil {
				return err
			}
			out.Secrets = append(out.Secrets, entry)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if out.EncryptedGroupInfo, err = r.Opaque(); err != nil {
		return nil, err
	}
	return out, nil
}

// Marshal encodes a Welcome.
func (welcome *Welcome) Marshal(w *mlstls.Writer) error {
	w.Uint16(welcome.CipherSuite)

	w.Vector(func(w *mlstls.Writer) error {
		for _, entry := range welcome.Secrets {
			w.Opaque(entry.NewMember)
			w.Opaque(entry.EncryptedGroupSecrets.KemOutput)
			w.Opaque(entry.EncryptedGroupSecrets.Ciphertext)
		}
		return nil
	})

	w.Opaque(welcome.EncryptedGroupInfo)
	return nil
}

// MarshalWelcome encodes a Welcome and returns the bytes.
func MarshalWelcome(welcome *Welcome) ([]byte, error) {
	w := mlstls.NewWriter(512)
	if err := welcome.Marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func writePSKIDs(w *mlstls.Writer, ids []PreSharedKeyID) {
	w.Vector(func(w *mlstls.Writer) error {
		for _, id := range ids {
			w.Uint8(uint8(id.Type))
			switch id.Type {
			case PSKTypeExternal:
				w.Opaque(id.ID)
			case PSKTypeResumption:
				w.Uint8(uint8(id.Usage))
				w.Opaque(id.GroupID)
				w.Uint64(id.Epoch)
			}
			w.Opaque(id.Nonce)
		}
		return nil
	})
}

func parsePSKIDs(r *mlstls.Reader) ([]PreSharedKeyID, error) {
	var out []PreSharedKeyID
	err := r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			rawType, err := r.Uint8()
			if err != nil {
				return err
			}
			id := PreSharedKeyID{Type: PSKType(rawType)}

			switch id.Type {
			case PSKTypeExternal:
				if id.ID, err = r.Opaque(); err != nil {
					return err
				}
			case PSKTypeResumption:
				usage, err := r.Uint8()
				if err != nil {
					return err
				}
				id.Usage = ResumptionPSKUsage(usage)
				if id.GroupID, err = r.Opaque(); err != nil {
					return err
				}
				if id.Epoch, err = r.Uint64(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("mls/messages: unknown PSK type %d", rawType)
			}

			if id.Nonce, err = r.Opaque(); err != nil {
				return err
			}
			out = append(out, id)
		}
		return nil
	})
	return out, err
}
