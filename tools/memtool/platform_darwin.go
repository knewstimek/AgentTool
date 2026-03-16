package memtool

import "fmt"

type darwinReader struct{}

func newProcessReader() ProcessReader { return &darwinReader{} }

func (r *darwinReader) Open(pid int, writable bool) error {
	return fmt.Errorf("memory tools are not supported on macOS due to System Integrity Protection (SIP)")
}

func (r *darwinReader) Close() {}

func (r *darwinReader) Regions() ([]MemoryRegion, error) {
	return nil, fmt.Errorf("not supported on macOS")
}

func (r *darwinReader) ReadMemory(address uint64, buf []byte) (int, error) {
	return 0, fmt.Errorf("not supported on macOS")
}

func (r *darwinReader) WriteMemory(address uint64, data []byte) (int, error) {
	return 0, fmt.Errorf("not supported on macOS")
}
