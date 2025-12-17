# husk
```
curl -sL https://raw.githubusercontent.com/jensbirk/husk/main/install.sh | bash
```

## Usage

### Install Globally
Sync packages defined in `husk.yaml` to your user profile (`~/.local/bin`):
```bash
husk install
```

### Project Shell (Flake-like)
Enter a shell with dependencies defined in the current directory's `husk.yaml`, without installing them globally:
```bash
husk shell
```

### Generations & Rollback
Husk saves a snapshot of your configuration after every successful global install.

List previous generations:
```bash
husk generations
```

Rollback to the previous generation:
```bash
husk rollback
```

Switch to a specific generation ID:
```bash
husk switch-generation <id>
```

## Configuration (husk.yaml)

You can define custom Nix channels (inputs) and packages:

```yaml
channels:
  unstable: "https://hydra.nixos.org/job/nixpkgs/trunk"
  stable: "https://hydra.nixos.org/job/nixos/release-23.11/nixpkgs"

packages:
  - ripgrep
  - go:
      channel: unstable
  - neovim:
      config: ./configs/neovim:.config/nvim

env:
  EDITOR: neovim
```