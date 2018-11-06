# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/).


## [Unreleased]

## [1.5.1]

### Fixed

* loca table corruption during subsetting. The loca table serialization code
  didn't properly detect suitable table format.

* Fixed checksum calculation for empty tables.

## [1.5.0] - 2017-02-13

### Added

* Support for reading TTF fonts from TTC files

### Changed

* Subset font naming is consistent now and depends on content


## [1.4.0] - 2014-09-21

### Added

* sbix table support


## [1.3.0] - 2014-09-10

### Removed

* Post table version 2.5


## [1.2.2] - 2014-08-29

### Fixed

* Ignore unsupported cmap table versions


## [1.2.1] - 2014-08-28

### Fixed

* Added missing Pathname require


## [1.2.0] - 2014-06-23

### Added

* Rubocop checks
* Ability to parse IO objects

### Changed

* Improved preferred family name selection


## [1.1.1] - 2014-02-24

### Changed

* Clarified licensing

### Removed

* comicsans.ttf


## [1.1.0] - 2014-01-21

### Added

* Improved Unicode astral planes support
* Support for cmap table formats 6, 10, 12
* RSpec-based specs

### Fixed

* Subsetting in JRuby


## [1.0.3] - 2011-10-11

### Added

* Authorship information


## 1.0.2 - 2011-08-08

### Fixed

* Ruby 1.9.2 segmentation fault on Enumerable#zip(range)


## 1.0.0 - 2011-04-02 [YANKED]

Initial release as a standalone gem



[Unreleased]: https://github.com/prawnpdf/ttfunk/compare/1.5.1...HEAD
[1.5.1]: https://github.com/prawnpdf/ttfunk/compare/1.5.0...1.5.1
[1.5.0]: https://github.com/prawnpdf/ttfunk/compare/1.4.0...1.5.0
[1.4.0]: https://github.com/prawnpdf/ttfunk/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/prawnpdf/ttfunk/compare/1.2.2...1.3.0
[1.2.2]: https://github.com/prawnpdf/ttfunk/compare/1.2.1...1.2.2
[1.2.1]: https://github.com/prawnpdf/ttfunk/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/prawnpdf/ttfunk/compare/1.1.1...1.2.0
[1.1.1]: https://github.com/prawnpdf/ttfunk/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/prawnpdf/ttfunk/compare/1.0.3...1.1.0
[1.0.3]: https://github.com/prawnpdf/ttfunk/compare/1.0.2...1.0.3
