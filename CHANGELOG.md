# Changelog

## v1.2.4

### Improved

- Implement hard link detection in directory size calculation

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