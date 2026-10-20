//go:build !windows

package confidentialinference

import "github.com/ebitengine/purego"

func openLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
}

func lookupSymbol(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}

// closeLibrary balances openLibrary. Call it only once every native handle
// outlives the library.
func closeLibrary(handle uintptr) {
	_ = purego.Dlclose(handle)
}
