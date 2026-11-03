package confidentialinference

import "syscall"

// purego.Dlopen is not available on Windows; the standard syscall package
// covers the same surface without extra dependencies.

func openLibrary(path string) (uintptr, error) {
	handle, err := syscall.LoadLibrary(path)
	return uintptr(handle), err
}

func lookupSymbol(handle uintptr, name string) (uintptr, error) {
	return syscall.GetProcAddress(syscall.Handle(handle), name)
}

// closeLibrary balances openLibrary. Call it only once every native handle
// outlives the library.
func closeLibrary(handle uintptr) {
	_ = syscall.FreeLibrary(syscall.Handle(handle))
}
