package memtool

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

type linuxReader struct {
	pid      int
	memFile  *os.File
	writable bool
}

func newProcessReader() ProcessReader {
	return &linuxReader{}
}

func (r *linuxReader) Open(pid int, writable bool) error {
	flag := os.O_RDONLY
	if writable {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), flag, 0)
	if err != nil {
		return fmt.Errorf("failed to open /proc/%d/mem: %w (check permissions or use sudo)", pid, err)
	}
	r.pid = pid
	r.memFile = f
	r.writable = writable
	return nil
}

func (r *linuxReader) Close() {
	if r.memFile != nil {
		r.memFile.Close()
		r.memFile = nil
	}
}

func (r *linuxReader) Regions() ([]MemoryRegion, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", r.pid))
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/%d/maps: %w", r.pid, err)
	}
	defer f.Close()

	var regions []MemoryRegion
	scanner := bufio.NewScanner(f)
	const maxRegions = 200_000

	for scanner.Scan() && len(regions) < maxRegions {
		region, ok := parseMapsLine(scanner.Text())
		if ok && strings.Contains(region.Protection, "r") {
			regions = append(regions, region)
		}
	}
	return regions, scanner.Err()
}

func (r *linuxReader) ReadMemory(address uint64, buf []byte) (int, error) {
	if r.memFile == nil {
		return 0, fmt.Errorf("process not opened")
	}
	// Guard against int64 overflow — addresses above MaxInt64 cannot be
	// passed to ReadAt which takes int64. (audit M5)
	if address > math.MaxInt64 {
		return 0, fmt.Errorf("address 0x%X exceeds int64 range", address)
	}
	n, err := r.memFile.ReadAt(buf, int64(address))
	if err != nil && n == 0 {
		return 0, fmt.Errorf("read at 0x%X: %w", address, err)
	}
	return n, nil
}

func (r *linuxReader) WriteMemory(address uint64, data []byte) (int, error) {
	if r.memFile == nil {
		return 0, fmt.Errorf("process not opened")
	}
	if !r.writable {
		return 0, fmt.Errorf("process opened read-only")
	}
	if address > math.MaxInt64 {
		return 0, fmt.Errorf("address 0x%X exceeds int64 range", address)
	}
	n, err := r.memFile.WriteAt(data, int64(address))
	if err != nil {
		return n, fmt.Errorf("write at 0x%X: %w", address, err)
	}
	return n, nil
}

// parseMapsLine parses "start-end perms offset dev inode pathname"
func parseMapsLine(line string) (MemoryRegion, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return MemoryRegion{}, false
	}

	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return MemoryRegion{}, false
	}
	start, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return MemoryRegion{}, false
	}
	end, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil || end <= start {
		return MemoryRegion{}, false
	}

	perms := fields[1]
	prot := "---"
	if len(perms) >= 3 {
		prot = string([]byte{perms[0], perms[1], perms[2]})
	}

	mapped := ""
	if len(fields) >= 6 {
		mapped = fields[5]
	}

	return MemoryRegion{
		BaseAddress: start,
		Size:        end - start,
		Protection:  prot,
		MappedFile:  mapped,
	}, true
}
