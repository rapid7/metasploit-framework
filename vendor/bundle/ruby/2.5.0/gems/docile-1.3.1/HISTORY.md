# HISTORY

## [Unreleased changes](http://github.com/ms-ati/docile/compare/v1.3.1...master)

  - ...

## [v1.3.1 (May 24, 2018)](http://github.com/ms-ati/docile/compare/v1.3.0...v1.3.1)

  - Special thanks to Taichi Ishitani (@taichi-ishitani):
    - Fix for when DSL object is also the block's context (#30)

## [v1.3.0 (Feb 7, 2018)](http://github.com/ms-ati/docile/compare/v1.2.0...v1.3.0)

  - Allow helper methods in block's context to call DSL methods
  - Add SemVer release policy explicitly
  - Standardize on double-quoted string literals
  - Workaround some more Travis CI shenanigans

## [v1.2.0 (Jan 11, 2018)](http://github.com/ms-ati/docile/compare/v1.1.5...v1.2.0)

  - Special thanks to Christina Koller (@cmkoller)
    - add DSL evaluation returning *return value of the block* (see `.dsl_eval_with_block_return`)
  - add an example to README
  - keep travis builds passing on old ruby versions

## [v1.1.5 (Jun 15, 2014)](http://github.com/ms-ati/docile/compare/v1.1.4...v1.1.5)

  - as much as possible, loosen version restrictions on development dependencies
  - clarify gemspec settings as much as possible
  - bump rspec dependency to 3.0.x

## [v1.1.4 (Jun 11, 2014)](http://github.com/ms-ati/docile/compare/v1.1.3...v1.1.4)

  - Special thanks to Ken Dreyer  (@ktdreyer):
    - make simplecov/coveralls optional for running tests \[[33834852c7](https://github.com/ms-ati/docile/commit/33834852c7849912b97e109e8c5c193579cc5e98)\]
    - update URL in gemspec \[[174e654a07](https://github.com/ms-ati/docile/commit/174e654a075c8350b3411b212cfb409bc605348a)\]

## [v1.1.3 (Feb 4, 2014)](http://github.com/ms-ati/docile/compare/v1.1.2...v1.1.3)

  - Special thanks to Alexey Vasiliev (@le0pard):
    - fix problem to catch NoMethodError from non receiver object
    - upgrade rspec format to new "expect" syntax

## [v1.1.2 (Jan 10, 2014)](http://github.com/ms-ati/docile/compare/v1.1.1...v1.1.2)

  - remove unnecessarily nested proxy objects (thanks @Ajedi32)!
  - documentation updates and corrections

## [v1.1.1 (Nov 26, 2013)](http://github.com/ms-ati/docile/compare/v1.1.0...v1.1.1)

  - documentation updates and corrections
  - fix Rubinius build in Travis CI

## [v1.1.0 (Jul 29, 2013)](http://github.com/ms-ati/docile/compare/v1.0.5...v1.1.0)

  - add functional-style DSL objects via `Docile#dsl_eval_immutable`

## [v1.0.5 (Jul 28, 2013)](http://github.com/ms-ati/docile/compare/v1.0.4...v1.0.5)

  - achieve 100% yard docs coverage
  - fix rendering of docs at http://rubydoc.info/gems/docile

## [v1.0.4 (Jul 25, 2013)](http://github.com/ms-ati/docile/compare/v1.0.3...v1.0.4)

  - simplify and clarify code
  - fix a minor bug where FallbackContextProxy#instance_variables would return
    symbols rather than strings on Ruby 1.8.x

## [v1.0.3 (Jul 6, 2013)](http://github.com/ms-ati/docile/compare/v1.0.2...v1.0.3)

  - instrument code coverage via SimpleCov and publish to Coveralls.io

## [v1.0.2 (Apr 1, 2013)](http://github.com/ms-ati/docile/compare/v1.0.1...v1.0.2)

  - allow passing parameters to DSL blocks (thanks @dslh!)

## [v1.0.1 (Nov 29, 2012)](http://github.com/ms-ati/docile/compare/v1.0.0...v1.0.1)

  - relaxed rspec and rake dependencies to allow newer versions
  - fixes to documentation

## [v1.0.0 (Oct 29, 2012)](http://github.com/ms-ati/docile/compare/1b225c8a27...v1.0.0)

  - Initial Feature Set
