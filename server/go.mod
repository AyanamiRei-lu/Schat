module github.com/AyanamiRei-lu/Schat/server

go 1.27

// This module deliberately has ZERO dependencies beyond the Go standard
// library, and deliberately does NOT import github.com/AyanamiRei-lu/Schat/protocol.
//
// That is an architectural guarantee, not a style preference. SCHAT.md
// section 7.2 promises that the relay server cannot decrypt user content. If the
// server binary contains no cryptographic code at all, that promise holds even
// if the server is fully compromised, and it holds for a verifier who simply
// runs `go list -deps ./...` rather than taking our word for it.
//
// Consequences to preserve when extending this module:
//
//   - Do not add a database driver. There is nothing to store.
//   - Do not add a YAML or TOML dependency; configuration is JSON, which the
//     standard library already parses (see internal/config).
//   - Do not import the protocol module, not even for a constant. Duplicate the
//     few wire constants that are needed (for example the 16-byte delivery
//     token) so that no crypto code is linked in.
