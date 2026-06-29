package memtool

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

// daclRewriteMu serializes the temporary DACL rewrite below. Without it, two
// concurrent force_dacl opens on the same target could interleave so that the
// second snapshots the first's temporary grant DACL as its "original" and later
// restores to that, leaving the target permanently open (TOCTOU). The critical
// section is microseconds and rarely contended, so a single global lock is fine.
var daclRewriteMu sync.Mutex

// openViaDACLRewrite is the opt-in (force_dacl) fallback used when a normal
// OpenProcess is denied by the target's DACL. It exploits a Windows access-check
// rule: the OWNER of a process object is implicitly granted READ_CONTROL and
// WRITE_DAC regardless of the DACL (unless an OWNER_RIGHTS SID, S-1-3-4, is
// present). So a caller running as the SAME user as the target can rewrite that
// target's DACL even after being denied PROCESS_VM_READ.
//
// Strategy:
//  1. Open the target with WRITE_DAC|READ_CONTROL (owner-implicit grant).
//  2. Save its current DACL so we can put it back byte-for-byte.
//  3. TEMPORARILY replace the DACL with a single ACE that grants ONLY the current
//     user the requested access, then open the VM handle. A handle's access
//     rights are fixed at OpenProcess time, so the handle keeps working after we
//     restore the DACL.
//  4. ALWAYS restore the original DACL.
//
// Why replace rather than append an allow ACE: in canonical ACL order deny ACEs
// are evaluated before allow ACEs, so appending an allow would not override an
// existing deny (whether on our user SID or a group we belong to). Replacing the
// DACL with a single allow-our-SID ACE sidesteps any deny. Granting only our own
// SID means no third party gains access during the brief window the DACL is
// relaxed.
//
// Boundaries (returns a descriptive error, target left untouched): a target owned
// by another user, running at a higher integrity level, carrying an OWNER_RIGHTS
// SID, or protected by PPL/anti-cheat cannot be opened this way -- those are
// kernel/integrity boundaries, not DACL ones, and step 1 (or step 3's re-open)
// will fail.
func (r *windowsReader) openViaDACLRewrite(pid int, access uint32) error {
	const ownerDaclAccess = windows.WRITE_DAC | windows.READ_CONTROL

	// Held across save -> grant -> reopen -> restore. Registered first so it
	// unlocks last (after the deferred restore and CloseHandle run, LIFO).
	daclRewriteMu.Lock()
	defer daclRewriteMu.Unlock()

	hDac, err := windows.OpenProcess(ownerDaclAccess, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("cannot obtain WRITE_DAC on PID %d (not owned by current user, has an OWNER_RIGHTS SID, or is higher integrity/PPL): %w", pid, err)
	}
	defer windows.CloseHandle(hDac) // LIFO: runs LAST, after the DACL is restored

	// Save the original DACL. origDacl points into origSD's Go-heap buffer; keep
	// origSD referenced (via the restore closure below) until restore completes.
	origSD, err := windows.GetSecurityInfo(hDac, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("GetSecurityInfo(PID %d): %w", pid, err)
	}
	origDacl, _, err := origSD.DACL()
	if err != nil {
		// No DACL present == no DACL-based restriction, so the original denial was
		// integrity/PPL based and this bypass cannot help. Bail without changes.
		return fmt.Errorf("PID %d has no DACL to bypass (denial is integrity/PPL based, not DACL): %w", pid, err)
	}

	sid, err := currentUserSID()
	if err != nil {
		return err
	}

	grant := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(access),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	// mergedSD == nil -> the resulting DACL contains ONLY our single grant ACE.
	newSD, err := windows.BuildSecurityDescriptor(nil, nil, grant, nil, nil)
	if err != nil {
		return fmt.Errorf("BuildSecurityDescriptor: %w", err)
	}
	newDacl, _, err := newSD.DACL()
	if err != nil {
		return fmt.Errorf("extract grant DACL: %w", err)
	}

	if err := windows.SetSecurityInfo(hDac, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, newDacl, nil); err != nil {
		return fmt.Errorf("SetSecurityInfo(grant) on PID %d: %w", pid, err)
	}
	// Restore the original DACL no matter what follows. Registered AFTER the grant
	// succeeded and BEFORE the re-open, so even a failed re-open restores. Runs
	// before the deferred CloseHandle (LIFO), while hDac still holds WRITE_DAC.
	defer func() {
		_ = windows.SetSecurityInfo(hDac, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, origDacl, nil)
	}()

	// Access rights are fixed at this call; restoring the DACL afterward does not
	// revoke them.
	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(PID %d) still denied after DACL rewrite (likely higher integrity or PPL): %w", pid, err)
	}

	r.handle = h
	r.pid = pid
	return nil
}

// currentUserSID returns the SID of the user running this process. The SID lives
// in a Go-heap buffer copied out by GetTokenInformation, so it stays valid after
// the token handle is closed.
func currentUserSID() (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("OpenProcessToken(query): %w", err)
	}
	defer tok.Close()

	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("GetTokenUser: %w", err)
	}
	return tu.User.Sid, nil
}
