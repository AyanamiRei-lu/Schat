package protocol

import "runtime"

// Zero overwrites b with zeros.
//
// SCS-1 lives by the rule that key material must exist in memory for the
// shortest possible time (SCHAT.md section 4.9 and 6.3). Go's garbage collector
// copies values and does not scrub freed memory, so relying on GC alone would
// leave root keys, chain keys and message keys sitting in the heap where a
// memory dump or a core file could recover them.
//
// Callers must Zero() a buffer immediately after its last use:
//
//	mk, err := DeriveMessageKey(ck, DirAToB, n, TypeText)
//	if err != nil {
//		return err
//	}
//	defer mk.Zero()
//
// The runtime.KeepAlive call matters: without it the compiler is permitted to
// treat b as dead once the loop ends and elide the write entirely, which would
// silently turn this function into a no-op.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroAll zeroes every slice it is given. It is a convenience for the common
// case of scrubbing several related buffers at once.
func ZeroAll(bufs ...[]byte) {
	for _, b := range bufs {
		Zero(b)
	}
}
