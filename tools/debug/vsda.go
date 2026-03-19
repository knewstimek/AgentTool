package debug

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// vsdbg sends a "handshake" reverse request with a base64 challenge.
// The client must sign it using vsda.node (a proprietary N-API module
// bundled with VS Code) and return the signature. Without this,
// vsdbg rejects the connection.
//
// Two signing strategies are available:
//  1. Native Go: Uses the reverse-engineered signing algorithm directly.
//     No external dependencies. Preferred method.
//  2. Node.js subprocess: Loads vsda.node via Node.js as a fallback.
//     Requires both vsda.node (VS Code) and Node.js on the system.

const vsdaSignTimeout = 5 * time.Second

// vsdaTable1 contains EULA text fragments used as HMAC-like salt.
// Extracted from vsda.node binary at RVA 0x36A20 (string pointer table).
// These are plain ASCII strings from Microsoft's VS Code license text.
var vsdaTable1 [10][]byte

// vsdaTable2 contains pseudo-random character sequences used as salt.
// Extracted from vsda.node binary at RVA 0x369C0 (string pointer table).
var vsdaTable2 [10][]byte

func init() {
	// Table data extracted from vsda.node binary via PE RVA analysis.
	// Hex-encoded to avoid JSON/string escaping issues with special chars.
	table1Hex := [10]string{
		"596f75206d6179206f6e6c79207573652074686520432f432b2b20457874656e73696f6e20666f722056697375616c2053747564696f20436f646520616e6420432320457874656e73696f6e20666f722056697375616c2053747564696f20436f6465",
		"776974682056697375616c2053747564696f20436f64652c2056697375616c2053747564696f206f722058616d6172696e2053747564696f20736f66747761726520746f2068656c7020796f7520646576656c6f7020616e64207465737420796f7572206170706c69636174696f6e732e",
		"54686520736f667477617265206973206c6963656e7365642c206e6f7420736f6c642e",
		"546869732061677265656d656e74206f6e6c7920676976657320796f7520736f6d652072696768747320746f207573652074686520736f6674776172652e",
		"4d6963726f736f667420726573657276657320616c6c206f7468657220726967687473",
		"596f75206d6179206e6f7420776f726b2061726f756e6420616e7920746563686e6963616c206c696d69746174696f6e7320696e2074686520736f6674776172653b",
		"7265766572736520656e67696e6565722c206465636f6d70696c65206f7220646973617373656d626c652074686520736f667477617265",
		"72656d6f76652c206d696e696d697a652c20626c6f636b206f72206d6f6469667920616e79206e6f7469636573206f66204d6963726f736f6674206f7220",
		"69747320737570706c6965727320696e2074686520736f6674776172652073686172652c207075626c6973682c2072656e742c206f72206c6561736520",
		"74686520736f6674776172652c206f722070726f766964652074686520736f6674776172652061732061207374616e642d616c6f6e6520686f7374656420617320736f6c7574696f6e20666f72206f746865727320746f207573652e",
	}
	table2Hex := [10]string{
		"562b792c2848607626415c40782b3b3447754b3c247a5d2e2e3f382377565a6e272a2b7d6a31455c246b30242f6c766b70623834364b3a6b662243495c596c2a6434202f202e522c7b20",
		"42252642483c2f27657b55603e463e6b73336c6b6753583e4554717b5673752d693c6b56637d2950284860774b6c5476755045443e424c41582943305831734e5c5b75342c48",
		"626b40774a722637682b4e5c604a666b3444246e6263644b656e5e566b4f483c274b4e3a2575564f274733657623292e24674d24722f3d3d7174595d504a5b",
		"2e6f77436f5c315c423a393634273432297b63303c712c3e5c5c3122202d20214031777d5874",
		"56272b7c69353f7d5d57504c537a65315745363b277d54673b3833763856327a7d6f7626782a",
		"24586a6d23583a76634b64596e30566e6b724c51444f7779223b202e3352425357255249644c4f5a3728474b52202f20313e287763696d653a35714473203f205b6c356235444b52203d2039",
		"3155484a5e3751742e535074633c513e363e23246a452b3e3e6522502a4d62207c20624c202f206048352768376e503a6f77202b207d7a61714442322c225c2838365861",
		"3b4a4e437b3662422c3e5232474d793e7421264a5e5253797d3232407950387c513b70683a5c6d6a563d784c23792729792b4e7c63",
		"2f764a7b234f6324786764754f245c3655523e435f35733f4d32585b65586d613a2955797278624b",
		"3f4d59222c345f62394c702279714775333768342e7d5d77232876624e30634b5e3f525d22763c584667245c4e5a605b4b36",
	}
	for i := 0; i < 10; i++ {
		vsdaTable1[i], _ = hex.DecodeString(table1Hex[i])
		vsdaTable2[i], _ = hex.DecodeString(table2Hex[i])
	}
}

// signVsdaChallenge signs a vsdbg handshake challenge.
// Uses native Go signing (reverse-engineered algorithm).
// Returns (signature, method, error) where method indicates which signer was used.
func signVsdaChallenge(challenge string) (string, string, error) {
	sig := signVsdaNative(challenge)
	return sig, "native-go", nil
}

// signVsdaNative implements vsda's signing algorithm in pure Go.
//
// Algorithm (reverse-engineered from vsda.node):
//   - Pick 3 random indices (0-9) for table lookups
//   - Buffer = input + table1[idx1] + table1[idx2] + table2[idx3]
//   - Hash = SHA-256(buffer)
//   - Output = str(idx1) + str(idx2) + str(idx3) + Base64(hash)
//
// The original uses MSVC rand() seeded with heap address + init value,
// but the verifier reconstructs the same computation from the 3-digit
// prefix, so any random indices produce a valid signature.
func signVsdaNative(input string) string {
	idx1 := rand.Intn(10)
	idx2 := rand.Intn(10)
	idx3 := rand.Intn(10)

	// Build buffer: input + table1[idx1] + table1[idx2] + table2[idx3]
	inputBytes := []byte(input)
	buf := make([]byte, 0, len(inputBytes)+len(vsdaTable1[idx1])+len(vsdaTable1[idx2])+len(vsdaTable2[idx3]))
	buf = append(buf, inputBytes...)
	buf = append(buf, vsdaTable1[idx1]...)
	buf = append(buf, vsdaTable1[idx2]...)
	buf = append(buf, vsdaTable2[idx3]...)

	hash := sha256.Sum256(buf)
	b64 := base64.StdEncoding.EncodeToString(hash[:])

	return strconv.Itoa(idx1) + strconv.Itoa(idx2) + strconv.Itoa(idx3) + b64
}

// signVsdaViaNode signs using vsda.node through a Node.js subprocess.
// This is the fallback method when native signing needs to be verified
// against the original implementation.
func signVsdaViaNode(challenge string) (string, error) {
	vsdaPath, err := findVsdaNode()
	if err != nil {
		return "", fmt.Errorf("vsda.node not found: %w (vsdbg requires VS Code's vsda module for handshake signing)", err)
	}

	nodePath, err := findNode()
	if err != nil {
		return "", fmt.Errorf("node not found: %w (needed to load vsda.node for vsdbg handshake)", err)
	}

	// Escape backslashes in paths for JS string literals
	escapedVsda := strings.ReplaceAll(vsdaPath, `\`, `\\`)
	escapedChallenge := strings.ReplaceAll(challenge, `'`, `\'`)

	script := fmt.Sprintf(
		`const v=require('%s');const s=new v.signer();process.stdout.write(s.sign('%s'))`,
		escapedVsda, escapedChallenge,
	)

	ctx, cancel := context.WithTimeout(context.Background(), vsdaSignTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, nodePath, "-e", script)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("vsda sign failed: %w", err)
	}

	sig := strings.TrimSpace(string(out))
	if sig == "" {
		return "", fmt.Errorf("vsda sign returned empty signature")
	}
	return sig, nil
}

// findVsdaNode searches for vsda.node in VS Code installation paths.
// VS Code stores it at: <install>/resources/app/node_modules.asar.unpacked/vsda/build/Release/vsda.node
func findVsdaNode() (string, error) {
	// Relative path within VS Code installation
	const relPath = "resources/app/node_modules.asar.unpacked/vsda/build/Release/vsda.node"

	candidates := vscodeInstallDirs()
	for _, dir := range candidates {
		p := filepath.Join(dir, relPath)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("searched %d VS Code locations", len(candidates))
}

// vscodeInstallDirs returns platform-specific VS Code installation directories.
func vscodeInstallDirs() []string {
	var dirs []string

	switch runtime.GOOS {
	case "windows":
		// Standard install + user install
		for _, envVar := range []string{"LOCALAPPDATA", "ProgramFiles"} {
			base := os.Getenv(envVar)
			if base == "" {
				continue
			}
			// VS Code uses a hash-like subdirectory under the main folder.
			// Glob for it: Programs/Microsoft VS Code/*/
			pattern := filepath.Join(base, "Programs", "Microsoft VS Code", "*")
			matches, _ := filepath.Glob(pattern)
			dirs = append(dirs, matches...)
			// Also check direct path (some installs)
			dirs = append(dirs, filepath.Join(base, "Programs", "Microsoft VS Code"))
		}

	case "darwin":
		dirs = append(dirs,
			"/Applications/Visual Studio Code.app/Contents",
		)
		home, _ := os.UserHomeDir()
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, "Applications", "Visual Studio Code.app", "Contents"),
			)
		}

	default: // linux
		dirs = append(dirs,
			"/usr/share/code",
			"/usr/lib/code",
			"/opt/visual-studio-code",
			"/snap/code/current/usr/share/code",
		)
		home, _ := os.UserHomeDir()
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, ".vscode"),
			)
		}
	}

	return dirs
}

// findNode locates a Node.js executable on the system.
func findNode() (string, error) {
	// Check PATH first
	if p, err := exec.LookPath("node"); err == nil {
		return p, nil
	}

	// Common locations
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		// nvm for windows, standard install
		candidates = []string{
			filepath.Join(os.Getenv("APPDATA"), "nvm", "nodejs", "node.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "nodejs", "node.exe"),
		}
		// Also check NVM4W symlink
		if nvm := os.Getenv("NVM_SYMLINK"); nvm != "" {
			candidates = append([]string{filepath.Join(nvm, "node.exe")}, candidates...)
		}
	default:
		candidates = []string{
			"/usr/local/bin/node",
			"/usr/bin/node",
		}
		home, _ := os.UserHomeDir()
		if home != "" {
			candidates = append(candidates,
				filepath.Join(home, ".nvm", "current", "bin", "node"),
			)
		}
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("node.js not found in PATH or common locations")
}
