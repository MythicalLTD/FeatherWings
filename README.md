# FeatherWings

Wings is featherpanel's server control plane, built for the rapidly changing gaming industry and designed to be
highly performant and secure. Wings provides an HTTP API allowing you to interface directly with running server
instances, fetch server logs, generate backups, and control all aspects of the server lifecycle.

In addition, Wings ships with a built-in SFTP server allowing your system to remain free of FeatherPanel specific
dependencies, and allowing users to authenticate with the same credentials they would normally use to access the Panel.

## Installation via APT (Debian/Ubuntu)

FeatherWings is available from the MythicalSystems APT repository in two channels:

| Package | Channel | When |
|---------|---------|------|
| `featherwings` | **stable** | Published GitHub releases (`v*` tags) |
| `featherwings-dev` | **nightly** | Every commit to `main` |

These packages conflict and cannot be installed at the same time. Switching channels (`apt install featherwings` ↔ `featherwings-dev`) replaces the other package automatically.

### Step-by-step

FeatherWings requires **Docker Engine (`docker-ce`)** from Docker's official apt repository. Install Docker **before** FeatherWings — do not use the distro `docker.io` package, as it conflicts with `docker-ce`.

Full Docker install docs: [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) · [Debian](https://docs.docker.com/engine/install/debian/)

1. Install Docker Engine (skip if `docker-ce` is already installed):

**Ubuntu**

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

**Debian** — same steps, but use `https://download.docker.com/linux/debian/gpg` and `https://download.docker.com/linux/debian` in the commands above. See the [Debian install guide](https://docs.docker.com/engine/install/debian/) for details.

If you previously installed `docker.io` or other unofficial Docker packages, remove them first as described in the Docker docs.

2. Import the FeatherWings repository GPG key:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.mythicalsystems.org/repository/keys/public.gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/mythicalsystems.gpg
sudo chmod a+r /etc/apt/keyrings/mythicalsystems.gpg
```

3. Add the repository:

```bash
ARCH="$(dpkg --print-architecture)"
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/mythicalsystems.gpg] https://apt.mythicalsystems.org/repository/MythicalSystems/ stable main" \
  | sudo tee /etc/apt/sources.list.d/mythicalsystems.list
```

4. Install FeatherWings (stable):

```bash
sudo apt-get update
sudo apt-get install -y featherwings
```

Or the nightly build:

```bash
sudo apt-get install -y featherwings-dev
```

5. Configure and start (if the install wizard did not run automatically):

```bash
sudo featherwings configure
sudo systemctl enable --now featherwings
```

### One-liner (stable)

Install Docker from Docker's official repository first (step 1 above), then:

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg && sudo install -d -m 0755 /etc/apt/keyrings && curl -fsSL https://apt.mythicalsystems.org/repository/keys/public.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/mythicalsystems.gpg && sudo chmod a+r /etc/apt/keyrings/mythicalsystems.gpg && ARCH="$(dpkg --print-architecture)" && echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/mythicalsystems.gpg] https://apt.mythicalsystems.org/repository/MythicalSystems/ stable main" | sudo tee /etc/apt/sources.list.d/mythicalsystems.list && sudo apt-get update && sudo apt-get install -y featherwings
```

To upgrade later:

```bash
sudo apt-get update && sudo apt-get install --only-upgrade featherwings
# or for nightly:
sudo apt-get update && sudo apt-get install --only-upgrade featherwings-dev
```

### Migrating from a manual install

If you previously installed FeatherWings by downloading the binary from GitHub releases, you can switch to APT without reconfiguring the panel.

1. Make sure your config is at `/etc/featherpanel/config.yml`. If it lives somewhere else, move or copy it there first:

```bash
sudo mkdir -p /etc/featherpanel
sudo cp /path/to/your/config.yml /etc/featherpanel/config.yml
```

2. Stop the old daemon and ensure Docker Engine (`docker-ce`) is installed from Docker's official apt repository (step 1 above):

```bash
sudo systemctl stop featherwings 2>/dev/null || true
sudo systemctl stop wings 2>/dev/null || true
```

3. Add the FeatherWings APT repository (steps 2–3 above), then install:

```bash
sudo apt-get update
sudo apt-get install -y featherwings
```

If `/etc/featherpanel/config.yml` already exists, the package keeps it and restarts the service. You do **not** need to run `featherwings configure` again.

4. Clean up the old manual install (optional but recommended):

```bash
sudo rm -f /etc/systemd/system/featherwings.service
sudo rm -f /etc/systemd/system/wings.service
sudo systemctl daemon-reload
sudo systemctl enable --now featherwings
```

The APT package installs the binary to `/usr/local/bin/featherwings` and provides a `wings` symlink for older scripts. After migration, use `apt upgrade` to update instead of replacing the binary by hand.

## Reporting Issues

Feel free to report any wings specific issues or feature requests in [GitHub Issues](https://github.com/mythicalltd/featherwings/issues/new).
