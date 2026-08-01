# Changelog

## v1.3.7.6 

### Fixed

- PBS backups that reported **0 bytes** to the panel now fall back to parsing `proxmox-backup-client` upload stats (`had to backup … of <size>`) when snapshot-list size is missing.
- PBS default archive name is now `root.pxar` (like PVE CT backups) so PBS UI shows `root.pxar.didx` for zip-download of the full archive; restore still tries `server.pxar` for legacy snapshots.
- FastDL public URLs now use `system.fastdl.public_hostname` (node FQDN) and the FastDL bind port instead of the panel hostname / Wings API port.
- FastDL per-server enabled/directory from the Panel is applied on Sync so FastDL survives server restart/power cycles; older panels that omit `fastdl` no longer wipe in-memory FastDL state.

## v1.3.7.5

### Added

- Proxmox Backup Server (PBS) backup adapter (`pbs`): stream server files with `proxmox-backup-client` (pxar) — no local tar.gz/zip when PBS is enabled; configure under `system.backups.pbs` in `config.yml`
- `GET /api/system/backups` reports the default backup adapter and PBS status for the panel
- Disk quota support for ext4/xfs using Linux project quotas (pelican/upstream!)
- Quiet config option to suppress the startup logo and reduce log verbosity (pelican/upstream!)
- Shared storage pool transfers to skip file copy when nodes share the same volume (pelican/upstream!)
- Server container shell exec endpoint at `POST /api/servers/{server}/exec` for one-shot `/bin/sh -c` commands via Docker exec (stdout/stderr/exit code)

### Improved

- Diagnostics uploads now use the MythicalSystems pastes API (`https://pastes.mythicalsystems.org/log`) with JSON payloads
- Upstream with pelican/upstream! (JWT scope security for download, upload, transfer, websocket, and backup tokens)
- Upstream with pelican/upstream! (64 MB max config file parse size to prevent OOM from oversized configs)
- Upstream with pelican/upstream! (conditional block I/O weight only when cgroup supports io.weight)
- Upstream with pelican/upstream! (mkdirAll returns created directories and chowns new parents to the server user)
- Upstream with pelican/upstream! (close Docker inspect and archive file descriptors after use)

### Fixed

- Upstream with pelican/upstream! (do not follow symlinks when performing chmod operations)
- Upstream with pelican/upstream! (SFTP subsystem payload length check before slicing)
- Upstream with pelican/upstream! (directories created via panel are no longer owned by root:root)
- Upstream with pelican/upstream! (remove quota projects when a server is deleted)
- Upstream with pelican/upstream! (remove machine-id file when a server is deleted)
- Upstream with pelican/upstream! (use golang.org/x/sys/unix for errno and statfs handling)

## v1.3.7.4

### Improved
- Upstream with pelican/upstream! (implement security changes from ptero 1.12.3)
- Upstream with pelican/upstream! (parser correctness fixes (integer precision, nil safety, multi-variable lookup, type coercion, IfValue, XML duplicates))

### Fixed

- Fixed a bug where the container interface was not being set correctly.

## v1.3.7.3

### Added

- Added support for directory size listing in the file manager.
- `GET /api/servers/{server}/files/archive/list` — list a directory inside an on-disk archive (zip, tar, …) without extracting.
- Added support for trash bin in the file manager.
- Added support for previewing contents inside an archive.

### Improved

- Faster server start on large file trees: disk quota preflight uses cached usage (refreshes in the background) instead of blocking on a full walk every boot.
- Recursive boot-time `chown` skips files that already match the configured Wings uid/gid, reducing syscall load when ownership is already correct.

## v1.3.7

### Improved

- Upstream with pelican/upstream! (fix: preserve boolean/numeric types when panel expands template)

### Added

- Support for BIG query, search inside the file manager for file contents and more!

## v1.3.3

### Added

- Only pull relevant image for this runtime (pelican/upstream)
- chown dir when creating (pelican/upstream)

## v1.2.4

### Improved

- Implement hard link detection in directory size calculation
- Updated DockerNetworkConfiguration struct to provide detailed comments on DNS settings and internal network behavior.
- Eggs Configs Were Broken!
- Ensure correct file ownership after installation

### Added

- Added FastDL allowing for enabling/disabling and directory specification.

## v1.1.4 

### Added 

- Enhance server transfer functionality to include backup

### Improved

- Fixed server online status

## v1.1.3

### Added

- Added rate limiting for websocket messages to prevent flooding.
- Implemented a limit on the number of concurrent websocket connections per server.
- Added support for user-specific denylisting of JWTs for enhanced security.
- Introduced a new endpoint for deauthorizing users from websocket connections.
- Native Hytale server support is now available out of the box!

### Improved
- Updated websocket message handling to improve error management and connection closure.
- Refactored websocket event handling to use a new Event type for better type safety.
- Improved server suspension handling by disconnecting all open websockets and SFTP clients when a server is suspended.
- Updated dependencies in go.mod to include golang.org/x/time for rate limiting functionality.

## v1.1.2

### Added

- Enable game server ip address allocation for macvlan driver. by @Freddo3000 & @madpeteguy
- Transfer backups and install logs by @QuintenQVD0
- Added support for SFTP key-only authentication, enhancing server security. Thanks to @rmartinoscar

## v1.1.1

### Improved

- Added improved backup download functionality.

## v1.1.0

### Added

* AlwaysOnline Support for Minecraft!
* Modules support for wings!
* Added a firewall manager for servers!
* Changed the logs upload url to featherpanel api!
* Introduced robust reverse proxy support, enabling seamless domain-based access and SSL integration for servers.
* Introduced a powerful server import feature, allowing seamless migration of files from remote SFTP/FTP sources directly into your servers.

## v1.0.9

### Added

* Added option to disable checksum verification for transfers

### Fixed

* Fixed an issue that prevented server transfers from working correctly within FeatherPanel.

## v1.0.8

### Fixed

* Fixed the pool overlaping issue if you had wings installed before :/

## v1.0.7

### Added

* Native KVM virtualization support added! You can now run full VMs directly inside FeatherPanel. Thanks to @nayskutzu.
* Vastly improved configuration editing experience via new API endpoints—enabling seamless and intuitive modification of Wings settings!

## v1.0.6

### Fixed

* Fixed an issue that prevented symlinks from being properly deleted

## v1.0.5

### Fixed

* Fixed an issue where files on the "File Denylist" could still be deleted if they were inside a folder.

### Added

* Added configurable maximum redirect limit for remote file downloads in the downloader settings.

### Removed

* Removed the configure command to streamline the experience FeatherWings is now even simpler to set up!

## v1.0.4

### Added

* Ability to request logs from a route!
* Added a dedicated route to generate and retrieve detailed diagnostic reports.
* Diagnostics reports are now uploaded using mclogs instead of the old pelican pastebin server :)
* Generated OpenAPI documentation is now available at `/api/docs/ui`, with specs exposed via `/api/docs/openapi.json`. Set `api.docs.enabled: false` in `config.yml` to disable serving the documentation.
* Introduced the ability to upload diagnostics reports directly to a user-specified URL!
* Added support for updating Wings from a custom download URL when permitted via `system.updates.enable_url`, including optional SHA256 verification.
* Added a protected `/api/system/self-update` endpoint with detailed upstream error feedback, mandatory checksums for direct URL updates, optional `disable_checksum` overrides, and new configuration toggles under `system.updates`.
* Added an authenticated host command execution endpoint at `/api/system/terminal/exec`, configurable through the new `system.host_terminal` settings (enabled by default).

### Fixed

* Resolved an issue that prevented archives from being created within subdirectories due to safepath restrictions
* Fixed an issue where the self-update command failed due to incorrect repository ownership configuration.

## v1.0.3

### Fixed

* Can't make archives inside new dirs!

## v1.0.2

### Fixed

* The default dir now gets created on wings launch!

### Added

* Ability to create more types of archives!

### Improved

* Support for the latest go version!

## v1.0.1

### Fixed
* **CRITICAL:** Fixed sync.Pool panic in archive compression causing "interface conversion: interface {} is *uint8, not []uint8" error - was incorrectly putting `&buf[0]` instead of `buf` into the pool
* Fixed file compression endpoint creating multiple archives instead of single archive - partial archives are now cleaned up on error to prevent accumulation when clients retry failed requests

## v1.0.0-netv2

### Added
* Support for custom headers for wings!

## v1.0.0-net

### Fixed
* Fixes networkings inside the wings network!

## v1.0.0

### Fixed
* Fixed a bug with unit testings not being okay
* Follow featherpanel api logic `fp_<key>`

### Added
* Users can now set ignore_certificate_errors: true in their config file under the api section, which is perfect for development environments with self-signed certificates. The command line flag will still override this setting if provided.
* Users can now view the log for each request that wings receives from the panel.

### Removed
* Removed deprecated `CTime()` function from filesystem package as it was unreliable and didn't actually return creation time
* Removed outdated TODO comments that were marked as resolved

### Improved
* Fixed panic-causing config access in file search functionality by implementing proper error handling with fallback defaults
* Modernized deprecated `reflect.SliceHeader` usage in filesystem operations with safer `unsafe.Slice` approach
* Implemented comprehensive test coverage for Unix filesystem operations (12 new test functions)
* Enhanced error handling and fallback mechanisms throughout the codebase