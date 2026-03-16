package memtool

// MemoryRegion represents a contiguous memory region in the target process.
type MemoryRegion struct {
	BaseAddress uint64
	Size        uint64
	Protection  string // "r--", "rw-", "r-x", "rwx"
	MappedFile  string
}

// ProcessReader provides access to a target process's memory.
// Implementations are platform-specific (Windows, Linux).
type ProcessReader interface {
	// Open attaches to the target process. writable=true requests write access.
	Open(pid int, writable bool) error

	// Close releases all handles.
	Close()

	// Regions returns the list of readable memory regions.
	Regions() ([]MemoryRegion, error)

	// ReadMemory reads bytes from the given virtual address.
	ReadMemory(address uint64, buf []byte) (int, error)

	// WriteMemory writes bytes to the given virtual address.
	// Requires Open(pid, writable=true).
	WriteMemory(address uint64, data []byte) (int, error)
}

// matchProtection checks if a region's protection matches the requested filter.
func matchProtection(regionProt, filter string) bool {
	switch filter {
	case "r":
		return len(regionProt) >= 1 && regionProt[0] == 'r'
	case "rw":
		return len(regionProt) >= 2 && regionProt[0] == 'r' && regionProt[1] == 'w'
	case "rx":
		return len(regionProt) >= 3 && regionProt[0] == 'r' && regionProt[2] == 'x'
	default:
		return true
	}
}
