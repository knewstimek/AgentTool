package memtool

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx = modKernel32.NewProc("VirtualQueryEx")
	procReadProcessMem = modKernel32.NewProc("ReadProcessMemory")
	procWriteProcessMem  = modKernel32.NewProc("WriteProcessMemory")
	procVirtualProtectEx = modKernel32.NewProc("VirtualProtectEx")
)

// MEMORY_BASIC_INFORMATION for 64-bit Windows.
type memoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	_                 [2]byte
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

const (
	memCommit = 0x1000

	pageReadonly         = 0x02
	pageReadWrite        = 0x04
	pageWriteCopy        = 0x08
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80

	processVMRead      = 0x0010
	processVMWrite     = 0x0020
	processVMOperation = 0x0008
	processQueryInfo   = 0x0400
)

type windowsReader struct {
	handle   windows.Handle
	pid      int
	writable bool
}

func newProcessReader() ProcessReader {
	return &windowsReader{}
}

func (r *windowsReader) Open(pid int, writable bool) error {
	access := uint32(processVMRead | processQueryInfo)
	if writable {
		access |= processVMWrite | processVMOperation
	}

	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d) failed: %w (run as Administrator if access denied)", pid, err)
	}
	r.handle = h
	r.pid = pid
	r.writable = writable
	return nil
}

func (r *windowsReader) Close() {
	if r.handle != 0 {
		windows.CloseHandle(r.handle)
		r.handle = 0
	}
}

func (r *windowsReader) Regions() ([]MemoryRegion, error) {
	if r.handle == 0 {
		return nil, fmt.Errorf("process not opened")
	}

	var regions []MemoryRegion
	var addr uintptr
	const maxRegions = 200_000

	for len(regions) < maxRegions {
		var mbi memoryBasicInfo
		ret, _, lastErr := procVirtualQueryEx.Call(
			uintptr(r.handle), addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			// VirtualQueryEx returns 0 both at normal end-of-address-space
			// (ERROR_INVALID_PARAMETER) and on real failures. If addr==0, we
			// haven't enumerated anything yet -- that's a real failure, not a
			// normal termination. Surface the error so agents know why 0 regions
			// were returned instead of silently succeeding with empty results.
			if addr == 0 {
				return nil, fmt.Errorf("VirtualQueryEx failed at base address for PID %d: %w (process may be protected (PPL/anti-cheat); try running as Administrator)", r.pid, lastErr)
			}
			break
		}

		if mbi.State == memCommit && isReadable(mbi.Protect) {
			regions = append(regions, MemoryRegion{
				BaseAddress: uint64(mbi.BaseAddress),
				Size:        uint64(mbi.RegionSize),
				Protection:  protectionString(mbi.Protect),
			})
		}

		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}

	return regions, nil
}

func (r *windowsReader) ReadMemory(address uint64, buf []byte) (int, error) {
	if r.handle == 0 {
		return 0, fmt.Errorf("process not opened")
	}
	if len(buf) == 0 {
		return 0, nil
	}

	var bytesRead uintptr
	ret, _, err := procReadProcessMem.Call(
		uintptr(r.handle), uintptr(address),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		n := int(bytesRead)
		if n > 0 {
			// Partial read succeeded: return the data we got with an error
			// so callers can use the partial result. This typically happens
			// when the read crosses a page boundary into unmapped memory.
			return n, fmt.Errorf("partial read at 0x%X: got %d of %d bytes (%w). Try a smaller length or align to page boundary (0x1000)", address, n, len(buf), err)
		}
		return 0, fmt.Errorf("read failed at 0x%X: %w. Address may be unmapped or protected -- try VirtualQueryEx (memtool scan) to find valid memory regions first", address, err)
	}
	return int(bytesRead), nil
}

func (r *windowsReader) WriteMemory(address uint64, data []byte) (int, error) {
	if r.handle == 0 {
		return 0, fmt.Errorf("process not opened")
	}
	if !r.writable {
		return 0, fmt.Errorf("process opened read-only (use write operation which opens with write access)")
	}
	if len(data) == 0 {
		return 0, nil
	}

	var bytesWritten uintptr
	ret, _, err := procWriteProcessMem.Call(
		uintptr(r.handle), uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret != 0 {
		return int(bytesWritten), nil
	}

	// Write failed — try changing page protection to PAGE_READWRITE,
	// retry write, then restore original protection.
	var oldProtect uint32
	vpRet, _, _ := procVirtualProtectEx.Call(
		uintptr(r.handle), uintptr(address),
		uintptr(len(data)), uintptr(pageReadWrite),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if vpRet == 0 {
		// VirtualProtectEx also failed — return original write error
		return int(bytesWritten), fmt.Errorf("WriteProcessMemory at 0x%X: %w", address, err)
	}

	// Retry write with relaxed protection
	ret, _, err = procWriteProcessMem.Call(
		uintptr(r.handle), uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	// Restore original protection regardless of write result
	var ignored uint32
	procVirtualProtectEx.Call(
		uintptr(r.handle), uintptr(address),
		uintptr(len(data)), uintptr(oldProtect),
		uintptr(unsafe.Pointer(&ignored)),
	)

	if ret == 0 {
		return int(bytesWritten), fmt.Errorf("WriteProcessMemory at 0x%X (after VirtualProtectEx): %w", address, err)
	}
	return int(bytesWritten), nil
}

func isReadable(protect uint32) bool {
	switch protect & 0xFF {
	case pageReadonly, pageReadWrite, pageWriteCopy,
		pageExecuteRead, pageExecuteReadWrite, pageExecuteWriteCopy:
		return true
	}
	return false
}

func protectionString(protect uint32) string {
	switch protect & 0xFF {
	case pageReadonly:
		return "r--"
	case pageReadWrite, pageWriteCopy:
		return "rw-"
	case pageExecuteRead:
		return "r-x"
	case pageExecuteReadWrite, pageExecuteWriteCopy:
		return "rwx"
	default:
		return fmt.Sprintf("0x%02X", protect&0xFF)
	}
}
