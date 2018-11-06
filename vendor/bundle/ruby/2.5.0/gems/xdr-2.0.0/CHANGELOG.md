# Changelog 

All notable changes to this project will be documented in this
file.  This project adheres to [Semantic Versioning](http://semver.org/).

As this project is pre 1.0, breaking changes may happen for minor version
bumps.  A breaking change will get clearly notified in this log.

## [1.0.0](https://github.com/stellar/ruby-stellar-base/compare/v0.1.0...v1.0.0)

### Added
- the `to_xdr` helpers can take a second parameter that will encode the resulting output to hex or base64 when requested.
- the `from_xdr` helpers can take a second parameter that will trigger a decode from hex or base64 of the provided string before decoding from xdr.

### Changed

- `from_xdr` raises an ArgumentError when the input data is not fully consumed
