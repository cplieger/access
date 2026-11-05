package accesstest

// Snapshot returns m's published state by value. fmt prints only the address
// of the atomic pointer that holds it, while a deep dumper such as go-spew
// walks into it, so a printing test prints this too.
func Snapshot(m *MemStore) any { return *m.snap.Load() }
