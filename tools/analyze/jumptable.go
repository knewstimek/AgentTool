package analyze

// x86 switch jump-table resolution for CFG traversal.
//
// MSVC compiles a dense switch into `jmp dword ptr [idx*4 + disp32]`, where
// disp32 is the absolute VA of a table of absolute code VAs (one per case). A
// plain CFG walk stops dead at this indirect jump because the targets live in
// data, so every basic block after a switch looks unreachable -- which is the
// dominant reason a real function start fails to CFG-reach an in-body query
// (forcing function_at to demote that query to low). Resolving the table feeds
// the case blocks back into the traversal as what they are: more of the SAME
// function's body.
//
// This recovers coverage that angr's CFGFast gets from full jump-table analysis,
// but stays deliberately narrow and safe:
//   - only the pure-disp32 form is resolved (no base register). A based index
//     (`[base + idx*4]`) is an array load, not a compiler switch table.
//   - entries are read only while they stay inside the same executable section,
//     with a hard cap, so a table that runs into adjacent data just stops early.
//   - the caller's existing walls still apply to every returned target: a target
//     at another known function start, or past an int3 padding run, is stopped
//     there. So a stray/overrun entry pointing into a neighbour is never walked
//     into -- the resolver widens reachability, it does not bypass the walls.

import (
	"encoding/binary"

	"golang.org/x/arch/x86/x86asm"
)

// jtResolver maps an indirect-jump instruction at section offset pos to the
// section offsets of its switch-case targets, or nil if it is not a resolvable
// jump table.
type jtResolver func(inst x86asm.Inst, pos int) []int

// maxJumpTableEntries bounds a single table read (runaway / non-table disp32).
const maxJumpTableEntries = 1024

// tableSection is one readable PE section the jump-table data may live in. The
// table itself can sit in .rdata/.data (the compiler's choice); only the case
// TARGETS must be code. Each holds the section's RVA and raw bytes.
type tableSection struct {
	rva  uint32
	data []byte
}

// makeJumpTableResolver returns a jtResolver. The case targets must land in the
// executable section described by execData/execRVA (that is where the CFG walk
// runs), but the table itself is looked up across tableSecs -- so a switch whose
// table the compiler placed in .rdata/.data still resolves. imageBase converts
// the absolute VAs the table stores into section offsets.
func makeJumpTableResolver(tableSecs []tableSection, execData []byte, execRVA uint32, imageBase uint64) jtResolver {
	execLo := uint64(execRVA)
	execHi := uint64(execRVA) + uint64(len(execData))
	return func(inst x86asm.Inst, pos int) []int {
		if inst.Op != x86asm.JMP || len(inst.Args) == 0 {
			return nil
		}
		m, ok := inst.Args[0].(x86asm.Mem)
		// Pure-disp32 SIB form: scale 4, an index register, NO base, positive disp.
		if !ok || m.Scale != 4 || m.Index == 0 || m.Base != 0 {
			return nil
		}
		// disp32 is an absolute VA; take it as unsigned so high-address tables
		// (imageBase >= 0x80000000) don't sign-extend to a negative int64.
		tableVA := uint64(uint32(m.Disp))
		if tableVA < imageBase {
			return nil
		}
		trva := tableVA - imageBase
		// Locate the section that holds the table (any readable section).
		var tdata []byte
		var tbase uint64
		for _, ts := range tableSecs {
			lo := uint64(ts.rva)
			hi := lo + uint64(len(ts.data))
			if trva >= lo && trva < hi {
				tdata, tbase = ts.data, lo
				break
			}
		}
		if tdata == nil {
			return nil // table not in any readable section -> can't read it
		}
		toff := int(trva - tbase)
		tn := len(tdata)
		var targets []int
		for k := 0; k < maxJumpTableEntries; k++ {
			p := toff + k*4
			if p+4 > tn {
				break
			}
			caseVA := uint64(binary.LittleEndian.Uint32(tdata[p:]))
			if caseVA < imageBase {
				break
			}
			crva := caseVA - imageBase
			// A case target must be CODE: inside the executable section. The first
			// entry that isn't ends the table (keeps a data array from over-reading).
			if crva < execLo || crva >= execHi {
				break
			}
			targets = append(targets, int(crva-execLo))
		}
		return targets
	}
}
