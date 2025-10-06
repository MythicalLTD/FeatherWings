# Changelog

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