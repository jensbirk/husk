package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ulikunitz/xz"
	"gopkg.in/yaml.v3"
)

// --- Configuration ---
const (
	StoreDir       = "/nix/store"
	CacheURL       = "https://cache.nixos.org"
	System         = "x86_64-linux"
	DefaultWorkers = 4
)

// Configuration Variables
var (
	ManifestFile    = "husk.yaml"
	LockFile        = "husk.lock"
	BinDir          = os.ExpandEnv("$HOME/.local/bin")
	ShareDir        = os.ExpandEnv("$HOME/.local/share")
	GLHacksDir      = os.ExpandEnv("$HOME/.local/share/husk/gl-hacks")
	SystemdUserDir  = os.ExpandEnv("$HOME/.config/systemd/user")
	EnvDir          = os.ExpandEnv("$HOME/.config/husk")
	StateDir        = os.ExpandEnv("$HOME/.local/state/husk")
	GenerationsDir  = filepath.Join(StateDir, "generations")
	BaseDir, _      = os.Getwd()
	DefaultChannels = map[string]string{
		"unstable": "https://hydra.nixos.org/job/nixpkgs/trunk",
		"stable":   "https://hydra.nixos.org/job/nixos/release-23.11/nixpkgs",
	}
	
	// Builtin Recipes for unfree/complex apps
	Recipes = map[string]string{
		"discord": `#!/bin/sh
set -e
echo "Downloading Discord..."
url="https://discord.com/api/download?platform=linux&format=tar.gz"
curl -L -o discord.tar.gz "$url"
tar -xzf discord.tar.gz

mkdir -p $OUT/bin $OUT/share/applications $OUT/share/icons/hicolor/256x256/apps
mv Discord/* $OUT/

# Create wrapper with --no-sandbox to fix SUID issues
cat > $OUT/bin/discord <<EOF
#!/bin/sh
exec $OUT/Discord --no-sandbox "\$@"
EOF
chmod +x $OUT/bin/discord

# Desktop file
cat > $OUT/share/applications/discord.desktop <<EOF
[Desktop Entry]
Name=Discord
Exec=$OUT/bin/discord
Icon=discord
Type=Application
Categories=Network;InstantMessaging;
EOF

# Icon
cp $OUT/discord.png $OUT/share/icons/hicolor/256x256/apps/discord.png
`,
	}
)

// --- Structs ---

type Manifest struct {
	Channels map[string]string `yaml:"channels"`
	Packages []interface{}     `yaml:"packages"`
	Env      map[string]string `yaml:"env"`
}

type PkgConfig struct {
	Channel string `yaml:"channel"`
	Build   string `yaml:"build"`
	Config  string `yaml:"config"`
	ID      string `yaml:"id"`
}

type LockFileStruct struct {
	Packages map[string]string      `json:"packages"`
	Closure  map[string]ClosureItem `json:"closure"`
	Files    map[string]string      `json:"files"`
}

type ClosureItem struct {
	StorePath   string   `json:"StorePath"`
	URL         string   `json:"URL"`
	References  []string `json:"References"`
	Type        string   `json:"Type,omitempty"`
	BuildScript string   `json:"BuildScript,omitempty"`
}

type NarInfo struct {
	StorePath  string
	URL        string
	References []string
}

// --- Entry Points ---

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]
	manifestPath := ManifestFile
	if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
		manifestPath = os.Args[2]
	}

	switch cmd {
	case "install", "sync":
		args := os.Args[2:]
		manifestToSync := ManifestFile

		if len(args) > 0 {
			// Check if first arg is a file
			if _, err := os.Stat(args[0]); err == nil {
				manifestToSync = args[0]
			} else {
				// Assume packages to install
				if err := addPackages(args); err != nil {
					fmt.Printf("❌ Failed to add packages: %v\n", err)
					os.Exit(1)
				}
			}
		}
		runSync(manifestToSync)
	case "shell", "dev":
		runShell(manifestPath)
	case "generations", "list-generations":
		listGenerations()
	case "rollback":
		rollbackGeneration()
	case "switch-generation":
		if len(os.Args) < 3 {
			fmt.Println("Usage: husk switch-generation <id>")
			os.Exit(1)
		}
		id, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Println("Invalid generation ID")
			os.Exit(1)
		}
		switchGeneration(id)
	case "gc":
		runGC()
	case "search":
		if len(os.Args) < 3 {
			fmt.Println("Usage: husk search <term>")
			os.Exit(1)
		}
		runSearch(os.Args[2])
	case "rm":
		args := os.Args[2:]
		if len(args) == 0 {
			fmt.Println("Usage: husk rm <package> [package...]")
			os.Exit(1)
		}
		if err := removePackages(args); err != nil {
			fmt.Printf("❌ Failed to remove packages: %v\n", err)
			os.Exit(1)
		}
		runSync(ManifestFile)
	case "hook":
		if len(os.Args) < 3 {
			fmt.Println("Usage: husk hook <bash|zsh>")
			os.Exit(1)
		}
		runHook(os.Args[2])
	case "activate":
		runActivate()
	case "help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Usage: husk <command> [arguments]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  install [path]       Install/Sync packages globally. Optional: path to husk.yaml")
	fmt.Println("  shell [path]         Start a shell with packages from husk.yaml (flake-like)")
	fmt.Println("  generations          List available generations")
	fmt.Println("  rollback             Rollback to the previous generation")
	fmt.Println("  switch-generation <id> Switch to a specific generation")
	fmt.Println("  gc                   Garbage collect unused store paths")
	fmt.Println("  search <term>        Search for packages (via Repology/Nix Unstable)")
	fmt.Println("  rm <package...>      Remove package(s) from husk.yaml and uninstall")
	fmt.Println("  help                 Show this help message")
}

// --- Commands ---

func runSync(manifestPath string) {
	checkEnv()
	updateBaseDir(manifestPath)

	m, err := loadManifest(manifestPath)
	if err != nil {
		fmt.Printf("⚠️  %s not found or invalid.\n", manifestPath)
		return
	}

	lock, _ := loadLockFile(filepath.Join(BaseDir, LockFile))

	// Resolve & Install
	newPkgs, needed, err := resolveAndInstall(m, lock)
	if err != nil {
		fmt.Printf("❌ Installation failed: %v\n", err)
		return
	}

	// Dotfiles
	newFiles := manageDotfiles(m, lock.Files)

	// Linking
	createGLEnv()
	for _, path := range newPkgs {
		linkBinaries(path)
		linkDesktop(path)
	}

	// Cleanup
	var validPaths []string
	for _, p := range newPkgs {
		validPaths = append(validPaths, p)
	}
	cleanupStaleWrappers(validPaths)

	// Global Env File
	envContent := "export XDG_DATA_DIRS=$HOME/.local/share:$XDG_DATA_DIRS\n"
	for k, v := range m.Env {
		envContent += fmt.Sprintf("export %s=\"%s\"\n", k, v)
	}
	os.WriteFile(filepath.Join(EnvDir, "env.sh"), []byte(envContent), 0644)

	// Save Lock
	finalLock := LockFileStruct{
		Packages: newPkgs,
		Closure:  needed,
		Files:    newFiles,
	}
	saveLockFile(filepath.Join(BaseDir, LockFile), newPkgs, needed, newFiles)

	// Save Generation
	if err := saveGeneration(m, &finalLock); err != nil {
		fmt.Printf("⚠️  Failed to save generation: %v\n", err)
	} else {
		fmt.Println("💾 Generation saved.")
	}

	fmt.Println("\n✅ System Synchronized.")
}

func runShell(manifestPath string) {
	updateBaseDir(manifestPath)

	m, err := loadManifest(manifestPath)
	if err != nil {
		fmt.Printf("⚠️  %s not found or invalid.\n", manifestPath)
		return
	}

	lock, _ := loadLockFile(filepath.Join(BaseDir, LockFile))

	newPkgs, needed, err := resolveAndInstall(m, lock)
	if err != nil {
		fmt.Printf("❌ Setup failed: %v\n", err)
		return
	}

	saveLockFile(filepath.Join(BaseDir, LockFile), newPkgs, needed, lock.Files)

	// Construct Environment
	newEnv := os.Environ()
	pathVar := os.Getenv("PATH")

	var paths []string
	for _, storePath := range newPkgs {
		binPath := filepath.Join(storePath, "bin")
		if _, err := os.Stat(binPath); err == nil {
			paths = append(paths, binPath)
		}
	}
	newPath := strings.Join(paths, string(os.PathListSeparator))
	if pathVar != "" {
		newPath = newPath + string(os.PathListSeparator) + pathVar
	}

	envMap := make(map[string]string)
	for _, e := range newEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	envMap["PATH"] = newPath
	for k, v := range m.Env {
		envMap[k] = v
	}

	var finalEnv []string
	for k, v := range envMap {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Printf("🚀 Entering husk shell...\n")
	execErr := syscall.Exec(shell, []string{shell}, finalEnv)
	if execErr != nil {
		fmt.Printf("Failed to spawn shell: %v\n", execErr)
	}
}

// --- Generations Logic ---

func listGenerations() {
	if _, err := os.Stat(GenerationsDir); os.IsNotExist(err) {
		fmt.Println("No generations found.")
		return
	}
	entries, err := os.ReadDir(GenerationsDir)
	if err != nil {
		fmt.Printf("Error reading generations: %v\n", err)
		return
	}

	var ids []int
	for _, e := range entries {
		if e.IsDir() {
			if id, err := strconv.Atoi(e.Name()); err == nil {
				ids = append(ids, id)
			}
		}
	}
	
	sort.Ints(ids)

	fmt.Printf("%-5s %-20s\n", "ID", "Date")
	for _, id := range ids {
		info, err := os.Stat(filepath.Join(GenerationsDir, strconv.Itoa(id)))
		date := "Unknown"
		if err == nil {
			date = info.ModTime().Format(time.RFC822)
		}
		fmt.Printf("%-5d %-20s\n", id, date)
	}
}

func saveGeneration(m *Manifest, lock *LockFileStruct) error {
	os.MkdirAll(GenerationsDir, 0755)

	entries, _ := os.ReadDir(GenerationsDir)
	maxID := 0
	for _, e := range entries {
		if id, err := strconv.Atoi(e.Name()); err == nil {
			if id > maxID {
				maxID = id
			}
		}
	}
	newID := maxID + 1
	genPath := filepath.Join(GenerationsDir, strconv.Itoa(newID))
	os.MkdirAll(genPath, 0755)

	// Save Manifest
	mData, _ := yaml.Marshal(m)
	os.WriteFile(filepath.Join(genPath, "husk.yaml"), mData, 0644)

	// Save Lock
	lData, _ := json.MarshalIndent(lock, "", "  ")
	os.WriteFile(filepath.Join(genPath, "husk.lock"), lData, 0644)

	return nil
}

func rollbackGeneration() {
	entries, _ := os.ReadDir(GenerationsDir)
	var ids []int
	for _, e := range entries {
		if id, err := strconv.Atoi(e.Name()); err == nil {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)

	if len(ids) < 2 {
		fmt.Println("No previous generation to rollback to.")
		return
	}

	prevID := ids[len(ids)-2] // Current is usually the last one
	switchGeneration(prevID)
}

func switchGeneration(id int) {
	genPath := filepath.Join(GenerationsDir, strconv.Itoa(id))
	if _, err := os.Stat(genPath); os.IsNotExist(err) {
		fmt.Printf("Generation %d not found.\n", id)
		return
	}

	fmt.Printf("🔄 Switching to generation %d...\n", id)

	// Load from generation
	manifestPath := filepath.Join(genPath, "husk.yaml")
	lockPath := filepath.Join(genPath, "husk.lock")

	m, err := loadManifest(manifestPath)
	if err != nil {
		fmt.Println("Error loading generation manifest.")
		return
	}
	lock, _ := loadLockFile(lockPath)

	// We set BaseDir to the generation path so config linking works relative to it?
	// Actually, config linking relies on relative paths in husk.yaml.
	// If the user used relative paths like "./configs/nvim", those won't exist in the generation folder.
	// This is a limitation of not copying the whole config tree.
	// For now, we update BaseDir to the original working dir (or keep it as is)?
	// Let's assume BaseDir is where the user invoked us, but that might be wrong for rollback.
	// Ideally, generations should be self-contained or we skip config linking if src missing.

	// Re-run installation
	newPkgs, _, err := resolveAndInstall(m, lock)
	if err != nil {
		fmt.Printf("❌ Install failed: %v\n", err)
		return
	}

	// Dotfiles
	// Warning: This might fail if source files are missing.
	// We'll proceed with best effort.
	// We might need to store the "original base dir" in the generation metadata if we want to support this properly.
	manageDotfiles(m, lock.Files)

	// Linking
	createGLEnv()
	for _, path := range newPkgs {
		linkBinaries(path)
		linkDesktop(path)
	}

	// Cleanup
	var validPaths []string
	for _, p := range newPkgs {
		validPaths = append(validPaths, p)
	}
	cleanupStaleWrappers(validPaths)

	// Env
	envContent := "export XDG_DATA_DIRS=$HOME/.local/share:$XDG_DATA_DIRS\n"
	for k, v := range m.Env {
		envContent += fmt.Sprintf("export %s=\"%s\"\n", k, v)
	}
	os.WriteFile(filepath.Join(EnvDir, "env.sh"), []byte(envContent), 0644)

	fmt.Printf("✅ Switched to generation %d.\n", id)
}

// --- Core Logic ---

func resolveAndInstall(m *Manifest, lock LockFileStruct) (map[string]string, map[string]ClosureItem, error) {
	// Merge Channels
	channels := make(map[string]string)
	for k, v := range DefaultChannels {
		channels[k] = v
	}
	for k, v := range m.Channels {
		channels[k] = v
	}

	// Parse Inputs
	nixCandidates := make(map[string]PkgConfig)
	for _, p := range m.Packages {
		if name, ok := p.(string); ok {
			nixCandidates[name] = PkgConfig{Channel: "unstable"}
		} else if pMap, ok := p.(map[string]interface{}); ok {
			for name, rawCfg := range pMap {
				b, _ := yaml.Marshal(rawCfg)
				var cfg PkgConfig
				yaml.Unmarshal(b, &cfg)
				if cfg.Channel == "" {
					cfg.Channel = "unstable"
				}
				nixCandidates[name] = cfg
			}
		}
	}

	// Resolve Nix Dependencies
	newPkgs := make(map[string]string)
	newClos := make(map[string]ClosureItem)

	var wg sync.WaitGroup
	resChan := make(chan struct {
		name, path string
		clos       map[string]ClosureItem
	}, len(nixCandidates))

	fmt.Printf("🧩 Resolving %d packages...\n", len(nixCandidates))

	for name, cfg := range nixCandidates {
		wg.Add(1)
		go func(n string, c PkgConfig) {
			defer wg.Done()
			url := channels[c.Channel]
			if url == "" {
				url = channels["unstable"]
			}
			pn, path, clos := queryHydraClosure(n, url, c.Build)
			if path != "" {
				resChan <- struct {
					name, path string
					clos       map[string]ClosureItem
				}{
					name: pn,
					path: path,
					clos: clos,
				}
			} else {
				fmt.Printf("❌ Failed to resolve: %s\n", n)
			}
		}(name, cfg)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	for res := range resChan {
		newPkgs[res.name] = res.path
		for k, v := range res.clos {
			newClos[k] = v
		}
	}

	// Calculate Downloads
	needed := make(map[string]ClosureItem)
	stack := []string{}
	for _, path := range newPkgs {
		stack = append(stack, extractHash(path))
	}

	// Closure traversal
	for len(stack) > 0 {
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := needed[h]; !exists {
			if item, ok := newClos[h]; ok {
				needed[h] = item
				for _, ref := range item.References {
					stack = append(stack, extractHash(ref))
				}
			} else if item, ok := lock.Closure[h]; ok {
				needed[h] = item
				for _, ref := range item.References {
					stack = append(stack, extractHash(ref))
				}
			}
		}
	}

	// Download & Install
	toDownload := make(map[string]ClosureItem)
	for h, item := range needed {
		// Check if exists on disk
		storeName := filepath.Base(item.StorePath)
		destPath := filepath.Join(StoreDir, storeName)
		if _, err := os.Stat(destPath); os.IsNotExist(err) {
			toDownload[h] = item
		}
	}

	if len(toDownload) > 0 {
		fmt.Printf("⬇️  Downloading %d store items...\n", len(toDownload))
		tasks := make(chan ClosureItem, len(toDownload))
		for _, item := range toDownload {
			tasks <- item
		}
		close(tasks)

		workers := DefaultWorkers
		if n := runtime.NumCPU(); n > workers {
			workers = n
		}
		var installWg sync.WaitGroup
		for i := 0; i < workers; i++ {
			installWg.Add(1)
			go func() {
				defer installWg.Done()
				for item := range tasks {
					installPackage(item)
				}
			}()
		}
		installWg.Wait()
	}

	return newPkgs, needed, nil
}

// --- Helpers ---

func updateBaseDir(manifestPath string) {
	absPath, absErr := filepath.Abs(manifestPath)
	if absErr == nil {
		BaseDir = filepath.Dir(absPath)
	}
}

func loadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	err = yaml.Unmarshal(data, &m)
	return &m, err
}

func loadLockFile(path string) (LockFileStruct, error) {
	lockData, err := os.ReadFile(path)
	var lock LockFileStruct
	if err == nil {
		json.Unmarshal(lockData, &lock)
	}
	if lock.Packages == nil {
		lock.Packages = make(map[string]string)
	}
	if lock.Closure == nil {
		lock.Closure = make(map[string]ClosureItem)
	}
	return lock, nil
}

func saveLockFile(path string, pkgs map[string]string, closure map[string]ClosureItem, files map[string]string) {
	finalLock := LockFileStruct{
		Packages: pkgs,
		Closure:  closure,
		Files:    files,
	}
	lBytes, _ := json.MarshalIndent(finalLock, "", "  ")
	os.WriteFile(path, lBytes, 0644)
}

// --- Utilities ---

func checkEnv() {
	if _, err := os.Stat(StoreDir); os.IsNotExist(err) {
		fmt.Printf("❌ Error: %s missing.\n", StoreDir)
		fmt.Println("   sudo mkdir -p /nix/store && sudo chown -R $USER /nix/store")
		os.Exit(1)
	}
	dirs := []string{BinDir, ShareDir, SystemdUserDir, EnvDir, GenerationsDir}
	for _, d := range dirs {
		os.MkdirAll(d, 0755)
	}
}

func extractHash(path string) string {
	parts := strings.Split(filepath.Base(path), "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// --- Network & Resolvers ---

func fetchNarInfo(hashVal string) (*NarInfo, error) {
	resp, err := http.Get(fmt.Sprintf("%s/%s.narinfo", CacheURL, hashVal))
	if err != nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch narinfo")
	}
	defer resp.Body.Close()

	info := &NarInfo{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "StorePath: ") {
			info.StorePath = strings.TrimPrefix(line, "StorePath: ")
		} else if strings.HasPrefix(line, "URL: ") {
			info.URL = strings.TrimPrefix(line, "URL: ")
		} else if strings.HasPrefix(line, "References: ") {
			refs := strings.TrimPrefix(line, "References: ")
			if refs != "" {
				info.References = strings.Fields(refs)
			}
		}
	}
	return info, nil
}

func queryHydraClosure(pkgName, channelURL, buildScript string) (string, string, map[string]ClosureItem) {
	effectiveBuildScript := buildScript
	if effectiveBuildScript == "" {
		if recipe, ok := Recipes[pkgName]; ok {
			effectiveBuildScript = recipe
		}
	}

	if effectiveBuildScript != "" {
		h := sha256.Sum256([]byte(effectiveBuildScript))
		hashStr := hex.EncodeToString(h[:])[:32]
		storePath := fmt.Sprintf("%s/%s-%s", StoreDir, hashStr, pkgName)
		closure := map[string]ClosureItem{
			hashStr: {
				StorePath:   storePath,
				Type:        "CustomBuild",
				BuildScript: effectiveBuildScript,
			},
		}
		return pkgName, storePath, closure
	}

	url := fmt.Sprintf("%s/%s.%s/latest", channelURL, pkgName, System)
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("User-Agent", "curl/7.68.0") // Mimic standard tool to avoid blocks
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil }}
	resp, err := client.Do(req)

	if err != nil || resp.StatusCode == 404 {
		return pkgName, "", nil
	}

	finalURL := resp.Request.URL.String()
	req, _ = http.NewRequest("GET", finalURL, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "curl/7.68.0")
	resp, err = client.Do(req)
	if err != nil {
		return pkgName, "", nil
	}
	defer resp.Body.Close()

	// Check if response is HTML (Anti-bot)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		fmt.Printf("⚠️  Hydra blocked request for %s (Anti-bot).\n", pkgName)
		return pkgName, "", nil
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return pkgName, "", nil
	}

	outputs, ok := data["buildoutputs"].(map[string]interface{})
	if !ok {
		return pkgName, "", nil
	}

	targetOutput := "out"
	if _, hasBin := outputs["bin"]; hasBin {
		targetOutput = "bin"
	}

	out, ok := outputs[targetOutput].(map[string]interface{})
	if !ok {
		return pkgName, "", nil
	}
	storePath, ok := out["path"].(string)
	if !ok {
		return pkgName, "", nil
	}

	closure := resolveClosure(storePath)
	return pkgName, storePath, closure
}

func resolveClosure(rootPath string) map[string]ClosureItem {
	fullTree := make(map[string]ClosureItem)
	stack := []string{extractHash(rootPath)}
	visited := make(map[string]bool)

	for len(stack) > 0 {
		currHash := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if visited[currHash] || currHash == "" {
			continue
		}
		visited[currHash] = true

		info, err := fetchNarInfo(currHash)
		if err != nil {
			continue
		}

		fullTree[currHash] = ClosureItem{
			StorePath:  info.StorePath,
			URL:        info.URL,
			References: info.References,
		}

		for _, ref := range info.References {
			h := extractHash(ref)
			if !visited[h] {
				stack = append(stack, h)
			}
		}
	}
	return fullTree
}

// --- NAR Parsing ---

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func readInt(r io.Reader) (uint64, error) {
	var n uint64
	err := binary.Read(r, binary.LittleEndian, &n)
	return n, err
}

func readString(r io.Reader) (string, error) {
	lenVal, err := readInt(r)
	if err != nil {
		return "", err
	}
	bytesVal, err := readExact(r, int(lenVal))
	if err != nil {
		return "", err
	}
	padding := (8 - (lenVal % 8)) % 8
	if padding > 0 {
		io.CopyN(io.Discard, r, int64(padding))
	}
	return string(bytesVal), nil
}

func unpackNarNode(r io.Reader, destPath string) error {
	_, err := readString(r) // tag
	if err != nil {
		return err
	}
	nodeTypeTag, _ := readString(r)
	if nodeTypeTag == "type" {
		typeVal, _ := readString(r)
		if typeVal == "regular" {
			return unpackRegular(r, destPath)
		} else if typeVal == "directory" {
			return unpackDirectory(r, destPath)
		} else if typeVal == "symlink" {
			return unpackSymlink(r, destPath)
		}
	}
	return fmt.Errorf("unknown node type at %s", destPath)
}

func unpackRegular(r io.Reader, destPath string) error {
	executable := false
	tag, _ := readString(r)
	if tag == "executable" {
		readString(r)
		executable = true
		tag, _ = readString(r)
	}
	if tag != "contents" {
		return fmt.Errorf("expected contents")
	}
	size, _ := readInt(r)
	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	_, err = io.CopyN(f, r, int64(size))
	f.Close()
	if err != nil {
		return err
	}
	padding := (8 - (size % 8)) % 8
	if padding > 0 {
		io.CopyN(io.Discard, r, int64(padding))
	}
	readString(r)
	mode := os.FileMode(0644)
	if executable {
		mode = 0755
	}
	os.Chmod(destPath, mode)
	return nil
}

func unpackDirectory(r io.Reader, destPath string) error {
	os.MkdirAll(destPath, 0755)
	for {
		tag, _ := readString(r)
		if tag == ")" {
			break
		}
		if tag != "entry" {
			return fmt.Errorf("expected entry")
		}
		readString(r)
		readString(r)
		name, _ := readString(r)
		readString(r)
		err := unpackNarNode(r, filepath.Join(destPath, name))
		if err != nil {
			return err
		}
		readString(r)
	}
	return nil
}

func unpackSymlink(r io.Reader, destPath string) error {
	readString(r)
	target, _ := readString(r)
	readString(r)
	os.Remove(destPath)
	return os.Symlink(target, destPath)
}

func installPackage(item ClosureItem) string {
	folderName := filepath.Base(item.StorePath)
	destPath := filepath.Join(StoreDir, folderName)

	if _, err := os.Stat(destPath); err == nil {
		if files, _ := os.ReadDir(destPath); len(files) > 0 {
			return folderName
		}
	}

	if item.Type == "CustomBuild" {
		fmt.Printf("🛠️  Building Custom: %s\n", folderName)
		os.MkdirAll(destPath, 0755)
		tmpScript := filepath.Join(os.TempDir(), "build.sh")
		os.WriteFile(tmpScript, []byte(item.BuildScript), 0755)
		cmd := exec.Command("/bin/bash", tmpScript)
		cmd.Env = append(os.Environ(), "OUT="+destPath)
		cmd.Dir = os.TempDir()
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("Build failed: %s\n", out)
			os.RemoveAll(destPath)
		}
		return folderName
	}

	url := fmt.Sprintf("%s/%s", CacheURL, item.URL)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Failed to download %s\n", url)
		return ""
	}
	defer resp.Body.Close()

	xzReader, err := xz.NewReader(resp.Body)
	if err != nil {
		fmt.Printf("XZ init failed: %v\n", err)
		return ""
	}
	readString(xzReader) // "nix-archive-1"
	if err := unpackNarNode(xzReader, destPath); err != nil {
		fmt.Printf("Unpack failed for %s: %v\n", folderName, err)
		os.RemoveAll(destPath)
		return ""
	}
	return folderName
}

// --- Linkers & Cleaners ---

func createGLEnv() {
	os.RemoveAll(GLHacksDir)
	os.MkdirAll(GLHacksDir, 0755)
}

func linkBinaries(storePath string) {
	binSrc := filepath.Join(storePath, "bin")
	files, err := os.ReadDir(binSrc)
	if err != nil {
		return
	}
	for _, f := range files {
		src := filepath.Join(binSrc, f.Name())
		dst := filepath.Join(BinDir, f.Name())

		// We add a marker line "# Generated by husk" to detect ownership
		script := fmt.Sprintf(`#!/bin/sh
# Generated by husk
export LIBGL_DRIVERS_PATH=/usr/lib/x86_64-linux-gnu/dri:/usr/lib64/dri
export LD_LIBRARY_PATH=%s:$LD_LIBRARY_PATH
export XDG_DATA_DIRS=%s/share:$XDG_DATA_DIRS
exec "%s" "$@"
`, GLHacksDir, storePath, src)

		os.Remove(dst)
		os.WriteFile(dst, []byte(script), 0755)
	}
}

func linkDesktop(storePath string) {
	shareSrc := filepath.Join(storePath, "share")
	filepath.Walk(shareSrc, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(shareSrc, path)
		dst := filepath.Join(ShareDir, rel)
		os.MkdirAll(filepath.Dir(dst), 0755)
		os.Remove(dst)
		if strings.HasSuffix(path, ".desktop") {
			content, _ := os.ReadFile(path)
			newContent := strings.ReplaceAll(string(content), filepath.Join(storePath, "bin"), BinDir)
			os.WriteFile(dst, []byte(newContent), 0755)
		} else {
			os.Symlink(path, dst)
		}
		return nil
	})
}

func manageDotfiles(m *Manifest, lockedFiles map[string]string) map[string]string {
	// Parse candidates
	nixCandidates := make(map[string]PkgConfig)
	for _, p := range m.Packages {
		if name, ok := p.(string); ok {
			nixCandidates[name] = PkgConfig{}
		} else if pMap, ok := p.(map[string]interface{}); ok {
			for name, rawCfg := range pMap {
				b, _ := yaml.Marshal(rawCfg)
				var cfg PkgConfig
				yaml.Unmarshal(b, &cfg)
				nixCandidates[name] = cfg
			}
		}
	}

	newFiles := make(map[string]string)
	for _, cfg := range nixCandidates {
		if cfg.Config == "" {
			continue
		}
		parts := strings.Split(cfg.Config, ":")
		src := parts[0]
		dest := ".config/" + filepath.Base(src)
		if len(parts) > 1 {
			dest = parts[1]
		}
		// BaseDir is now updated to the manifest directory
		absSrc := filepath.Join(BaseDir, strings.TrimSpace(src))
		absDest := filepath.Join(os.Getenv("HOME"), strings.TrimSpace(dest))
		if _, err := os.Stat(absSrc); err == nil {
			newFiles[strings.TrimSpace(dest)] = absSrc
			os.MkdirAll(filepath.Dir(absDest), 0755)
			if info, err := os.Lstat(absDest); err == nil {
				if info.Mode()&os.ModeSymlink == 0 {
					os.Rename(absDest, absDest+".bak")
				} else {
					os.Remove(absDest)
				}
			}
			os.Symlink(absSrc, absDest)
			fmt.Printf("🔗 Linked %s\n", dest)
		}
	}
	for f := range lockedFiles {
		if _, ok := newFiles[f]; !ok {
			p := filepath.Join(os.Getenv("HOME"), f)
			os.Remove(p)
			fmt.Printf("🧹 Unlinked %s\n", f)
		}
	}
	return newFiles
}

// cleanupStaleWrappers scans ~/.local/bin for files created by us
// that point to Nix store paths NOT in the valid set.
func cleanupStaleWrappers(validPaths []string) {
	validMap := make(map[string]bool)
	for _, p := range validPaths {
		validMap[p] = true
	}

	files, err := os.ReadDir(BinDir)
	if err != nil {
		return
	}

	for _, f := range files {
		path := filepath.Join(BinDir, f.Name())
		// Only check small files (wrappers)
		info, err := os.Stat(path)
		if err != nil || info.Size() > 10240 {
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sContent := string(content)

		// Identify our wrappers
		if strings.Contains(sContent, "Generated by husk") {
			// Find what store path it points to
			// Simple heuristic: look for "/nix/store/"
			idx := strings.Index(sContent, "/nix/store/")
			if idx != -1 {
				// Find end of path (next quote or space or newline)
				rest := sContent[idx:]
				end := strings.IndexAny(rest, "\" \n")
				if end != -1 {
					storePath := rest[:end]

					// Check if the storePath starts with any valid path
					found := false
					for valid := range validMap {
						if strings.HasPrefix(storePath, valid) {
							found = true
							break
						}
					}

					if !found {
						fmt.Printf("🧹 Removing stale wrapper: %s\n", f.Name())
						os.Remove(path)
					}
				}
			}
		}
	}
}

// --- Garbage Collection ---

func runGC() {
	fmt.Println("🧹 Starting Garbage Collection...")

	// 1. Identify Live Paths
	keepPaths := make(map[string]bool)

	// From Generations
	genEntries, _ := os.ReadDir(GenerationsDir)
	for _, e := range genEntries {
		if !e.IsDir() {
			continue
		}
		lockPath := filepath.Join(GenerationsDir, e.Name(), "husk.lock")
		lock, err := loadLockFile(lockPath)
		if err != nil {
			continue
		}
		for _, item := range lock.Closure {
			keepPaths[item.StorePath] = true
		}
	}

	fmt.Printf("found %d live store paths from %d generations.\n", len(keepPaths), len(genEntries))

	// 2. Scan Store
	storeEntries, err := os.ReadDir(StoreDir)
	if err != nil {
		fmt.Printf("❌ Error reading store: %v\n", err)
		return
	}

	// 3. Sweep
	deletedCount := 0
	var freedSpace int64 = 0

	for _, entry := range storeEntries {
		fullPath := filepath.Join(StoreDir, entry.Name())
		if !keepPaths[fullPath] {
			// Get size for reporting
			var size int64
			filepath.Walk(fullPath, func(_ string, info os.FileInfo, err error) error {
				if err == nil {
					size += info.Size()
				}
				return nil
			})

			if err := os.RemoveAll(fullPath); err == nil {
				deletedCount++
				freedSpace += size
			} else {
				fmt.Printf("⚠️ Failed to delete %s: %v\n", entry.Name(), err)
			}
		}
	}

	fmt.Printf("✅ GC Complete. Removed %d paths. Freed %s.\n", deletedCount, formatBytes(freedSpace))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// --- Search ---

type RepologyItem struct {
	Repo        string `json:"repo"`
	SrcName     string `json:"srcname"`
	Version     string `json:"version"`
	Summary     string `json:"summary"`
	VisibleName string `json:"visiblename"`
}

func runSearch(term string) {
	fmt.Printf("🔍 Searching for '%s' in nix_unstable...\n", term)
	
	url := fmt.Sprintf("https://repology.org/api/v1/projects/?search=%s&inrepo=nix_unstable", term)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "husk-cli/0.0.1 (github.com/jensbirk/husk)")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ Search failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("❌ Search API error: %s\n", resp.Status)
		return
	}

	// Repology returns a map: "pkgname" -> [list of versions/repos]
	// Since we filtered by inrepo=nix_unstable, we should get relevant entries.
	var results map[string][]RepologyItem
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		fmt.Printf("❌ Failed to parse results: %v\n", err)
		return
	}

	if len(results) == 0 {
		fmt.Println("No results found.")
		return
	}

	// Flatten and Sort
	var hits []RepologyItem
	for _, items := range results {
		for _, item := range items {
			if item.Repo == "nix_unstable" {
				hits = append(hits, item)
			}
		}
	}
	
	// Sort by SrcName (package name)
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].SrcName < hits[j].SrcName
	})

	fmt.Printf("%-30s %-15s %s\n", "Package", "Version", "Description")
	fmt.Println(strings.Repeat("-", 80))
	
	count := 0
	for _, h := range hits {
		desc := h.Summary
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}
		fmt.Printf("%-30s %-15s %s\n", h.SrcName, h.Version, desc)
		count++
		if count >= 20 {
			fmt.Println("... (more results hidden)")
			break
		}
	}
}

func addPackages(pkgs []string) error {
	m, err := loadManifest(ManifestFile)
	if err != nil {
		// If manifest doesn't exist, create a new one
		if os.IsNotExist(err) {
			fmt.Println("✨ Creating new husk.yaml...")
			m = &Manifest{
				Channels: DefaultChannels,
				Packages: []interface{}{},
				Env:      map[string]string{},
			}
		} else {
			return err
		}
	}

	dirty := false
	existing := make(map[string]bool)
	for _, p := range m.Packages {
		if name, ok := p.(string); ok {
			existing[name] = true
		} else if pMap, ok := p.(map[string]interface{}); ok {
			for k := range pMap {
				existing[k] = true
			}
		}
	}

	for _, pkg := range pkgs {
		if !existing[pkg] {
			m.Packages = append(m.Packages, pkg)
			dirty = true
			fmt.Printf("➕ Added %s to husk.yaml\n", pkg)
		} else {
			fmt.Printf("ℹ️  %s already in husk.yaml\n", pkg)
		}
	}

	if dirty {
		data, err := yaml.Marshal(m)
		if err != nil {
			return err
		}
		return os.WriteFile(ManifestFile, data, 0644)
	}
	return nil
}

func removePackages(pkgsToRemove []string) error {
	m, err := loadManifest(ManifestFile)
	if err != nil {
		return err // Cannot remove from non-existent manifest
	}

	pkgsToRemoveMap := make(map[string]bool)
	for _, p := range pkgsToRemove {
		pkgsToRemoveMap[p] = true
	}

	var newPackages []interface{}
	dirty := false

	for _, p := range m.Packages {
		keep := true
		if name, ok := p.(string); ok {
			if pkgsToRemoveMap[name] {
				keep = false
				fmt.Printf("➖ Removed %s from husk.yaml\n", name)
			}
		} else if pMap, ok := p.(map[string]interface{}); ok {
			// Assume only one key for pkgMap, e.g. "go: {channel: unstable}"
			for k := range pMap {
				if pkgsToRemoveMap[k] {
					keep = false
					fmt.Printf("➖ Removed %s from husk.yaml\n", k)
				}
				break // Only check first key if multiple existed
			}
		}

		if keep {
			newPackages = append(newPackages, p)
		} else {
			dirty = true
		}
	}

	if !dirty {
		fmt.Println("ℹ️  No packages to remove found in husk.yaml.")
		return nil
	}

	m.Packages = newPackages
	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(ManifestFile, data, 0644)
}

// --- Autoload / Hook ---

func runHook(shell string) {
	switch shell {
	case "bash":
		fmt.Println(`_husk_hook() {
  eval "$(husk activate)"
};
if [[ "$PROMPT_COMMAND" != *"_husk_hook"* ]]; then
  export PROMPT_COMMAND="_husk_hook;$PROMPT_COMMAND"
fi`)
	case "zsh":
		fmt.Println(`_husk_hook() {
  eval "$(husk activate)"
}
typeset -a precmd_functions
if [[ -z ${precmd_functions[(r)_husk_hook]} ]]; then
  precmd_functions+=(_husk_hook)
fi`)
	default:
		fmt.Println("Unsupported shell. Supported: bash, zsh")
		os.Exit(1)
	}
}

func runActivate() {
	cwd, _ := os.Getwd()
	activeRoot := os.Getenv("HUSK_ACTIVE")
	projectRoot, found := findProjectRoot(cwd)

	// Helper to print export commands
	printExport := func(key, value string) {
		fmt.Printf("export %s=\"%s\"\n", key, value)
	}
	printUnset := func(key string) {
		fmt.Printf("unset %s\n", key)
	}

	// Case 1: Already active in the correct root
	if found && activeRoot == projectRoot {
		return // Do nothing
	}

	// Case 2: Leaving an active project (Deactivate)
	if activeRoot != "" && activeRoot != projectRoot {
		// Restore PATH
		oldPath := os.Getenv("HUSK_OLD_PATH")
		if oldPath != "" {
			printExport("PATH", oldPath)
			printUnset("HUSK_OLD_PATH")
		}
		
		// Restore other envs
		// (Simple restoration for now: look for HUSK_OLD_ENV_ prefix in current env is hard in Go without iterating all)
		// We iterate os.Environ() to find backups
		for _, e := range os.Environ() {
			if strings.HasPrefix(e, "HUSK_OLD_ENV_") {
				parts := strings.SplitN(e, "=", 2)
				key := parts[0]
				val := parts[1]
				origKey := strings.TrimPrefix(key, "HUSK_OLD_ENV_")
				printExport(origKey, val)
				printUnset(key)
			}
		}

		printUnset("HUSK_ACTIVE")
		// Continue to see if we need to activate a new one
	}

	// Case 3: Activate new project
	if found {
		lockPath := filepath.Join(projectRoot, LockFile)
		manifestPath := filepath.Join(projectRoot, ManifestFile)

		// We need lockfile for speed and safety
		if _, err := os.Stat(lockPath); os.IsNotExist(err) {
			// Print to stderr so it doesn't break eval
			fmt.Fprintf(os.Stderr, "husk: Found husk.yaml but no lockfile. Run 'husk install' to enable autoload.\n")
			return
		}

		lock, err := loadLockFile(lockPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "husk: Error loading lockfile: %v\n", err)
			return
		}

		// Verify store paths exist
		var paths []string
		missing := false
		for _, storePath := range lock.Packages {
			if _, err := os.Stat(storePath); os.IsNotExist(err) {
				missing = true
				break
			}
			binPath := filepath.Join(storePath, "bin")
			if _, err := os.Stat(binPath); err == nil {
				paths = append(paths, binPath)
			}
		}

		if missing {
			fmt.Fprintf(os.Stderr, "husk: Some packages are missing. Run 'husk install'.\n")
			return
		}

		// Load manifest for Env vars
		m, err := loadManifest(manifestPath)
		if err == nil {
			for k, v := range m.Env {
				// Backup existing
				if currVal, exists := os.LookupEnv(k); exists {
					printExport("HUSK_OLD_ENV_"+k, currVal)
				}
				printExport(k, v)
			}
		}

		// Construct new PATH
		currentPath := os.Getenv("PATH")
		newPath := strings.Join(paths, string(os.PathListSeparator))
		if currentPath != "" {
			newPath = newPath + string(os.PathListSeparator) + currentPath
		}

		printExport("HUSK_OLD_PATH", currentPath)
		printExport("PATH", newPath)
		printExport("HUSK_ACTIVE", projectRoot)
		
		fmt.Fprintf(os.Stderr, "husk: Loaded environment from %s\n", projectRoot)
	}
}

func findProjectRoot(startDir string) (string, bool) {
	dir := startDir
	for {
		if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}


