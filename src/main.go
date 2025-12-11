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
	"strings"
	"sync"

	"github.com/ulikunitz/xz"
	"gopkg.in/yaml.v3"
)

// --- Configuration ---
const (
	StoreDir      = "/nix/store"
	CacheURL      = "https://cache.nixos.org"
	System        = "x86_64-linux"
	DefaultWorkes = 4
)

// Configuration Variables
var (
	ManifestFile   = "husk.yaml"
	LockFile       = "husk.lock"
	BinDir         = os.ExpandEnv("$HOME/.local/bin")
	ShareDir       = os.ExpandEnv("$HOME/.local/share")
	GLHacksDir     = os.ExpandEnv("$HOME/.local/share/husk/gl-hacks")
	SystemdUserDir = os.ExpandEnv("$HOME/.config/systemd/user")
	EnvDir         = os.ExpandEnv("$HOME/.config/husk")
	BaseDir, _     = os.Getwd()
	Channels       = map[string]string{
		"unstable": "https://hydra.nixos.org/job/nixpkgs/trunk",
		"stable":   "https://hydra.nixos.org/job/nixos/release-23.11/nixpkgs",
	}
)

// --- Structs ---

type Manifest struct {
	Packages []interface{}     `yaml:"packages"`
	GUIs     []interface{}     `yaml:"guis"`
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

	switch os.Args[1] {
	case "install", "sync":
		manifestPath := ManifestFile // Default to "husk.yaml"
		if len(os.Args) > 2 {
			manifestPath = os.Args[2]
		}
		runSync(manifestPath)
	case "help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Usage: husk <command> [arguments]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  install [path]   Install/Sync packages. Optional: path to husk.yaml")
	fmt.Println("  help             Show this help message")
}

func runSync(manifestPath string) {
	checkEnv()

	// Update BaseDir to the directory of the manifest file so relative paths in yaml work
	absPath, absErr := filepath.Abs(manifestPath)
	if absErr == nil {
		BaseDir = filepath.Dir(absPath)
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Printf("⚠️  %s not found.\n", manifestPath)
		return
	}
	var m Manifest
	yaml.Unmarshal(data, &m)

	// 1. Parse Inputs
	nixCandidates := make(map[string]PkgConfig)
	var flatPkgs []string

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

	fm := NewFlatpakManager()
	fm.EnsureRemote()
	for _, g := range m.GUIs {
		if name, ok := g.(string); ok {
			flatPkgs = append(flatPkgs, name)
		} else if gMap, ok := g.(map[string]interface{}); ok {
			for _, rawCfg := range gMap {
				b, _ := yaml.Marshal(rawCfg)
				var cfg PkgConfig
				yaml.Unmarshal(b, &cfg)
				if cfg.ID != "" {
					flatPkgs = append(flatPkgs, cfg.ID)
				}
			}
		}
	}

	// 2. Load Lockfile
	// We look for husk.lock in the same directory as the manifest
	lockPath := filepath.Join(BaseDir, LockFile)
	lockData, _ := os.ReadFile(lockPath)
	var lock LockFileStruct
	json.Unmarshal(lockData, &lock)
	if lock.Packages == nil {
		lock.Packages = make(map[string]string)
	}
	if lock.Closure == nil {
		lock.Closure = make(map[string]ClosureItem)
	}

	// 3. Resolve Nix Dependencies
	newPkgs := make(map[string]string)
	newClos := make(map[string]ClosureItem)

	var wg sync.WaitGroup
	resChan := make(chan struct {
		name, path string
		clos       map[string]ClosureItem
	}, len(nixCandidates))

	fmt.Printf("🧩 Resolving %d packages from %s...\n", len(nixCandidates), manifestPath)

	for name, cfg := range nixCandidates {
		wg.Add(1)
		go func(n string, c PkgConfig) {
			defer wg.Done()
			url := Channels[c.Channel]
			if url == "" {
				url = Channels["unstable"]
			}
			pn, path, clos := queryHydraClosure(n, url, c.Build)
			if path != "" {
				resChan <- struct {
					name, path string
					clos       map[string]ClosureItem
				}{pn, path, clos}
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
		fmt.Printf("   ✅ Resolved: %s\n", res.name)
	}

	// 4. Calculate Downloads
	needed := make(map[string]ClosureItem)
	stack := []string{}
	for _, path := range newPkgs {
		stack = append(stack, extractHash(path))
	}
	for len(stack) > 0 {
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := needed[h]; !exists {
			if item, ok := newClos[h]; ok {
				needed[h] = item
				for _, ref := range item.References {
					stack = append(stack, extractHash(ref))
				}
			}
		}
	}

	// 5. Download & Install
	if len(needed) > 0 {
		fmt.Printf("⬇️  Downloading/Verifying %d store items...\n", len(needed))
		tasks := make(chan ClosureItem, len(needed))
		for _, item := range needed {
			tasks <- item
		}
		close(tasks)

		workers := DefaultWorkes
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

	// 6. Dotfiles & Flatpaks
	newFiles := manageDotfiles(nixCandidates, lock.Files)
	fm.InstallAndPrune(flatPkgs)

	// 7. Linking & Cleanup
	createGLEnv()
	for _, path := range newPkgs {
		linkBinaries(path)
		linkDesktop(path)
	}

	// Run the garbage collector to remove binaries for packages no longer in newPkgs
	var validPaths []string
	for _, p := range newPkgs {
		validPaths = append(validPaths, p)
	}
	cleanupStaleWrappers(validPaths)

	// 8. Generate Env File
	envContent := "export XDG_DATA_DIRS=$HOME/.local/share:$XDG_DATA_DIRS\n"
	for k, v := range m.Env {
		envContent += fmt.Sprintf("export %s=\"%s\"\n", k, v)
	}
	os.WriteFile(filepath.Join(EnvDir, "env.sh"), []byte(envContent), 0644)

	// 9. Save Lock
	finalLock := LockFileStruct{
		Packages: newPkgs,
		Closure:  needed,
		Files:    newFiles,
	}
	lBytes, _ := json.MarshalIndent(finalLock, "", "  ")
	os.WriteFile(lockPath, lBytes, 0644)

	fmt.Println("\n✅ System Synchronized.")
}

// --- Utilities ---

func checkEnv() {
	if _, err := os.Stat(StoreDir); os.IsNotExist(err) {
		fmt.Printf("❌ Error: %s missing.\n", StoreDir)
		fmt.Println("   sudo mkdir -p /nix/store && sudo chown -R $USER /nix/store")
		os.Exit(1)
	}
	dirs := []string{BinDir, ShareDir, SystemdUserDir, EnvDir}
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
	if buildScript != "" {
		h := sha256.Sum256([]byte(buildScript))
		hashStr := hex.EncodeToString(h[:])[:32]
		storePath := fmt.Sprintf("%s/%s-%s", StoreDir, hashStr, pkgName)
		closure := map[string]ClosureItem{
			hashStr: {
				StorePath:   storePath,
				Type:        "CustomBuild",
				BuildScript: buildScript,
			},
		}
		return pkgName, storePath, closure
	}

	url := fmt.Sprintf("%s/%s.%s/latest", channelURL, pkgName, System)
	req, _ := http.NewRequest("HEAD", url, nil)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil }}
	resp, err := client.Do(req)

	if err != nil || resp.StatusCode == 404 {
		return pkgName, "", nil
	}

	finalURL := resp.Request.URL.String()
	req, _ = http.NewRequest("GET", finalURL, nil)
	req.Header.Set("Accept", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		return pkgName, "", nil
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return pkgName, "", nil
	}

	outputs, ok := data["buildoutputs"].(map[string]interface{})
	if !ok {
		return pkgName, "", nil
	}
	out, ok := outputs["out"].(map[string]interface{})
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

// --- Flatpak Integration ---

type FlatpakManager struct {
	cmd string
}

func NewFlatpakManager() *FlatpakManager {
	path, _ := exec.LookPath("flatpak")
	return &FlatpakManager{cmd: path}
}

func (fm *FlatpakManager) EnsureRemote() {
	if fm.cmd == "" {
		return
	}
	exec.Command(fm.cmd, "remote-add", "--user", "--if-not-exists", "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo").Run()
}

func (fm *FlatpakManager) InstallAndPrune(desired []string) {
	if fm.cmd == "" {
		return
	}
	out, _ := exec.Command(fm.cmd, "list", "--user", "--app", "--columns=application").Output()
	installed := strings.Split(string(out), "\n")
	instMap := make(map[string]bool)
	for _, l := range installed {
		if strings.TrimSpace(l) != "" {
			instMap[strings.TrimSpace(l)] = true
		}
	}
	desiredMap := make(map[string]bool)
	var needed []string
	for _, pkg := range desired {
		desiredMap[pkg] = true
		if !instMap[pkg] {
			needed = append(needed, pkg)
		}
	}
	if len(needed) > 0 {
		fmt.Printf("📺 Installing %d Flatpaks...\n", len(needed))
		args := append([]string{"install", "--user", "-y", "flathub"}, needed...)
		cmd := exec.Command(fm.cmd, args...)
		cmd.Run()
	}
	var toRemove []string
	for inst := range instMap {
		if !desiredMap[inst] {
			toRemove = append(toRemove, inst)
		}
	}
	if len(toRemove) > 0 {
		fmt.Printf("🗑️  Pruning %d Flatpaks...\n", len(toRemove))
		args := append([]string{"uninstall", "--user", "-y"}, toRemove...)
		exec.Command(fm.cmd, args...).Run()
	}
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

func manageDotfiles(pkgs map[string]PkgConfig, lockedFiles map[string]string) map[string]string {
	newFiles := make(map[string]string)
	for _, cfg := range pkgs {
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