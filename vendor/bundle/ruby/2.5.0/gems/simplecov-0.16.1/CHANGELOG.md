0.16.1 (2018-03-16)
===================

## Bugfixes

* Include the LICENSE in the distributed gem again (accidentally removed in 0.16.0). (thanks @tas50)

0.16.0 (2018-03-15)
===================

## Enhancements

* Relax version constraint on `docile`, per SemVer
* exception that occurred on exit is available as `exit_exception`! See [#639](https://github.com/colszowka/simplecov/pull/639)  (thanks @thomas07vt)
* Performance: processing results now runs from 2.5x to 3.75x faster. See [#662](https://github.com/colszowka/simplecov/pull/662) (thanks @BMorearty & @eregon)
* Decrease gem size by only shipping lib and docs

## Bugfixes

* (breaking) Stop handling string filters as regular expressions, use the dedicated regex filter if you need that behaviour. See [#616](https://github.com/colszowka/simplecov/pull/616) (thanks @yujinakayama)
* Avoid overwriting the last coverage results on unsuccessful test runs. See [#625](https://github.com/colszowka/simplecov/pull/625) (thanks @thomas07vt)
* Don't crash on invalid UTF-8 byte sequences. (thanks @BMorearty)

0.15.1 (2017-09-11) ([changes](https://github.com/colszowka/simplecov/compare/v0.15.0...v0.15.1))
=======

## Bugfixes

* Filter directories outside SimpleCov.root that have it as a prefix. See [#617](https://github.com/colszowka/simplecov/pull/617) (thanks @jenseng)
* Fix standard rails profile rails filter (didn't work). See [#618](https://github.com/colszowka/simplecov/pull/618) (thanks @jenseng again!)

0.15.0 (2017-08-14) ([changes](https://github.com/colszowka/simplecov/compare/v0.14.1...v0.15.0))
=======

## Enhancements

* Ability to use regex filters for removing files from the output. See [#589](https://github.com/colszowka/simplecov/pull/589) (thanks @jsteel)

## Bugfixes

* Fix merging race condition when running tests in parallel and merging them. See [#570](https://github.com/colszowka/simplecov/pull/570) (thanks @jenseng)
* Fix relevant lines for unloaded files - comments, skipped code etc. are correctly classified as irrelevant. See [#605](https://github.com/colszowka/simplecov/pull/605) (thanks @odlp)
* Allow using simplecov with frozen-string-literals enabled. See [#590](https://github.com/colszowka/simplecov/pull/590) (thanks @pat)
* Make sure Array Filter can use all other filter types. See [#589](https://github.com/colszowka/simplecov/pull/589) (thanks @jsteel)
* Make sure file names use `Simplecov.root` as base avoiding using full absolute project paths. See [#589](https://github.com/colszowka/simplecov/pull/589) (thanks @jsteel)

0.14.1 2017-03-18 ([changes](https://github.com/colszowka/simplecov/compare/v0.14.0...v0.14.1))
========

## Bugfixes

* Files that were skipped as a whole/had no relevant coverage could lead to Float errors. See [#564](https://github.com/colszowka/simplecov/pull/564) (thanks to @stevehanson for the report in [#563](https://github.com/colszowka/simplecov/issues/563))

0.14.0 2017-03-15 ([changes](https://github.com/colszowka/simplecov/compare/v0.13.0...v0.14.0))
==========

## Enhancements

* Officially support JRuby 9.1+ going forward (should also work with previous releases). See [#547](https://github.com/colszowka/simplecov/pull/547) (ping @PragTob when encountering issues)
* Add Channel group to Rails profile, when `ActionCable` is loaded. See [#492](https://github.com/colszowka/simplecov/pull/492) (thanks @BenMorganIO)
* Stop `extend`ing instances of `Array` and `Hash` during merging results avoiding problems frozen results while manually merging results. See [#558](https://github.com/colszowka/simplecov/pull/558) (thanks @aroben)

## Bugfixes

* Fix parallel_tests when a thread ends up running no tests. See [#533](https://github.com/colszowka/simplecov/pull/533) (thanks @cshaffer)
* Skip the `:nocov:` comments along with the code that they skip. See [#551](https://github.com/colszowka/simplecov/pull/551) (thanks @ebiven)
* Fix crash when Home environment variable is unset. See [#482](https://github.com/colszowka/simplecov/pull/482) (thanks @waldyr)
* Make track_files work again when explicitly setting it to nil. See [#463](https://github.com/colszowka/simplecov/pull/463) (thanks @craiglittle)
* Do not overwrite .last_run.json file when refuse_coverage_drop option is enabled and the coverage has dropped (lead to you being able to just rerun tests and everything was _fine_). See [#553](https://github.com/colszowka/simplecov/pull/553) (thanks @Miloshes)

0.13.0 2017-01-25 ([changes](https://github.com/colszowka/simplecov/compare/v0.12.0...v0.13.0))
==========

## Enhancements

* Faster run times when a very large number of files is loaded into SimpleCov. See [#520](https://github.com/colszowka/simplecov/pull/520) (thanks @alyssais)
* Only read in source code files that are actually used (faster when files are ignored etc.). See [#540](https://github.com/colszowka/simplecov/pull/540) (thanks @yui-knk)

## Bugfixes

* Fix merging of resultsets if a file is missing on one side. See [#513](https://github.com/colszowka/simplecov/pull/513) (thanks @hanazuki)
* Fix Ruby 2.4 deprecation warnings by using Integer instead of Fixnum. See [#523](https://github.com/colszowka/simplecov/pull/523) (thanks @nobu)
* Force Ruby 2 to json 2. See [dc7417d50](https://github.com/colszowka/simplecov/commit/dc7417d5049b1809cea214314c15dd93a5dd964f) (thanks @amatsuda)
* Various other gem dependency fixes for different gems on different ruby versions. (thanks @amatsuda)

0.12.0 2016-07-02 ([changes](https://github.com/colszowka/simplecov/compare/v0.11.2...v0.12.0))
=================

## Enhancements

* Add support for JSON versions 2.x

## Bugfixes

* Fix coverage rate of the parallel_tests. See [#441](https://github.com/colszowka/simplecov/pull/441) (thanks @sinsoku)
* Fix a regression on old rubies that failed to work with the recently introduced frozen VERSION string. See [#461](https://github.com/colszowka/simplecov/pull/461) (thanks @leafle)

0.11.2 2016-02-03 ([changes](https://github.com/colszowka/simplecov/compare/v0.11.1...v0.11.2))
=================

## Enhancements

* Do not globally pollute Array and Hash with `merge_resultset` utility methods. See [#449](https://github.com/colszowka/simplecov/pull/449) (thanks @amatsuda)
* Do not `mkdir_p` the `coverage_path` on every access of the method (See [#453](https://github.com/colszowka/simplecov/pull/453) (thanks @paddor)
* Fixes a Ruby warning related to the `track_files` configuration. See [#447](https://github.com/colszowka/simplecov/pull/447) (thanks @craiglittle)
* Add a group for background jobs to default Rails profile. See [#442](https://github.com/colszowka/simplecov/pull/442) (thanks @stve)

## Bugfixes

* Fix root_filter evaluates SimpleCov.root before initialization. See [#437](https://github.com/colszowka/simplecov/pull/437) (thanks @tmtm)

0.11.1 2015-12-01 ([changes](https://github.com/colszowka/simplecov/compare/v0.11.0...v0.11.1))
=================

## Enhancements

## Bugfixes

* Fixed regression in `MultiFormatter.[]` with multiple arguments. See [#431](https://github.com/colszowka/simplecov/pull/431) (thanks @dillondrobena)

0.11.0 2015-11-29 ([changes](https://github.com/colszowka/simplecov/compare/v0.10.0...v0.11.0))
=================

## Enhancements

* Added `SimpleCov.minimum_coverage_by_file` for per-file coverage thresholds. See [#392](https://github.com/colszowka/simplecov/pull/392) (thanks @ptashman)
* Added `track_files` configuration option to specify a glob to always include in coverage results, whether or not those files are required. By default, this is enabled in the Rails profile for common Rails directories. See [#422](https://github.com/colszowka/simplecov/pull/422) (thanks @hugopeixoto)
* Speed up `root_filter` by an order of magnitude. See [#396](https://github.com/colszowka/simplecov/pull/396) (thanks @raszi)

## Bugfixes

* Fix warning about global variable `$ERROR_INFO`. See [#400](https://github.com/colszowka/simplecov/pull/400) (thanks @amatsuda)
* Actually recurse upward looking for `.simplecov`, as claimed by the documentation, rather than only the working directory. See [#423](https://github.com/colszowka/simplecov/pull/423) (thanks @alexdowad)

0.10.0 2015-04-18 ([changes](https://github.com/colszowka/simplecov/compare/v0.9.2...v0.10.0))
=================

## Enhancements

 * Add writeup about using with Spring to README. See [#341](https://github.com/colszowka/simplecov/issues/341) (thanks @swrobel and @onebree)
 * Add support to pass in an Array when creating filter groups (original PR #104)
 * Filter `/vendor/bundle` by default. See [#331](https://github.com/colszowka/simplecov/pull/331) (thanks @andyw8)
 * Add some helpful singleton methods to the version string.
 * Allow array to be passed in a filter. See [375](https://github.com/colszowka/simplecov/pull/375) (thanks @JanStevens)
 * Enforce consistent code formatting with RuboCop.

## Bugfixes

 * Fix order dependencies in unit tests. See [#376](https://github.com/colszowka/simplecov/pull/376) (thanks @hugopeixoto)
 * Only run the at_exit behaviors if the current PID matches the PID that called SimpleCov.start. See [#377](https://github.com/colszowka/simplecov/pull/377) (thanks @coderanger)

0.9.2, 2015-02-18 ([changes](https://github.com/colszowka/simplecov/compare/v0.9.1...v0.9.2))
=================

This is a minor bugfix release for simplecov-html, released as `0.9.0`. Due to the tight version constraint in the gemspec
a new release of simplecov had to be shipped to allow using simplecov-html `~> 0.9.0`.

  * The browser back / forward button should now work again. See [#36](https://github.com/colszowka/simplecov-html/pull/36) and
    [#35](https://github.com/colszowka/simplecov-html/pull/35). Thanks @whatasunnyday and @justinsteele for submitting PRs to fix this.
  * Fix "warning: possibly useless use of a variable in void context" See [#31](https://github.com/colszowka/simplecov-html/pull/31). Thanks @cbandy
  * Always use binary file format. See [#32](https://github.com/colszowka/simplecov-html/pull/32). Thanks @andy128k
  * Avoid slow file output with JRuby/Windows. See [#16](https://github.com/colszowka/simplecov-html/pull/16). Thanks @pschambacher

Other than the release includes a bunch of mostly documentation improvements:

  * Update Rails path for Rails 4+. See [#336](https://github.com/colszowka/simplecov/pull/336). Thanks @yazinsai
  * Encourage use of .simplecov to avoid lost files. See [#338](https://github.com/colszowka/simplecov/pull/338). thanks @dankohn
  * Specified in the gemspec that simplecov needs ruby 1.8.7. See [#343](https://github.com/colszowka/simplecov/pull/343). thanks @iainbeeston
  * Fix mispointed link in CHANGELOG.md. See [#353](https://github.com/colszowka/simplecov/pull/353). Thanks @dleve123
  * Improve command name docs. See [#356](https://github.com/colszowka/simplecov/pull/356). Thanks @gtd



0.9.1, 2014-09-21 ([changes](https://github.com/colszowka/simplecov/compare/v0.9.0...v0.9.1))
=================

## Bugfixes

 * In 0.9.0, we introduced a regression that made SimpleCov no-op mode fail on Ruby 1.8, while
   dropping 1.8 support altogether is announced only for v1.0. This has been fixed.
   See [#333](https://github.com/colszowka/simplecov/issues/333) (thanks (@sferik)


0.9.0, 2014-07-17 ([changes](https://github.com/colszowka/simplecov/compare/v0.8.2...v0.9.0))
=================

**A warm welcome and big thank you to the new contributors [@xaviershay](https://github.com/xaviershay), [@sferik](https://github.com/sferik) and especially [@bf4](https://github.com/bf4) for tackling a whole lot of issues and pull requests for this release!**

## Enhancements

  * New interface to specify multiple formatters.
    See [#317](https://github.com/colszowka/simplecov/pull/317) (thanks @sferik)
  * Document in the README how to exclude code from coverage reports,
    and that the feature shouldn't be abused for skipping untested
    private code.
    See [#304](https://github.com/colszowka/simplecov/issues/304)
  * Clarify Ruby version support.
    See [#279](https://github.com/colszowka/simplecov/pull/279) (thanks @deivid-rodriguez)

## Bugfixes

  * Ensure calculations return Floats, not Fixnum or Rational. Fixes segfaults with mathn.
    See [#245](https://github.com/colszowka/simplecov/pull/245) (thanks to @bf4)
  * Using `Kernel.exit` instead of exit to avoid uncaught throw :IRB_EXIT when
    exiting irb sessions.
    See [#287](https://github.com/colszowka/simplecov/pull/287) (thanks @wless1)
    See [#285](https://github.com/colszowka/simplecov/issues/285)
  * Does not look for .simplecov in ~/ when $HOME is not set.
    See [#311](https://github.com/colszowka/simplecov/pull/311) (thanks @lasseebert)
  * Exit with code only if it's Numeric > 0.
    See [#302](https://github.com/colszowka/simplecov/pull/302) (thanks @hajder)
  * Make default filter case insensitive.
    See [#280](https://github.com/colszowka/simplecov/pull/280) (thanks @ryanatball)
  * Improve regexp that matches functional tests.
    See [#276](https://github.com/colszowka/simplecov/pull/276) (thanks @sferik)
  * Fix TravisCI [#272](https://github.com/colszowka/simplecov/pull/272) [#278](https://github.com/colszowka/simplecov/pull/278), [#302](https://github.com/colszowka/simplecov/pull/302)
  * Fix global config load.
    See [#311](https://github.com/colszowka/simplecov/pull/311) (thanks @lasseebert)

v0.8.2, 2013-11-20 ([changes](https://github.com/colszowka/simplecov/compare/v0.8.1...v0.8.2))
==================

## Bugfixes

  * Replaced the locking behaviour [via lockfile gem](https://github.com/colszowka/simplecov/pull/185) with
    plain Ruby explicit file locking when merging results. This should make simplecov merging to behave well
    on Windows again.
    See [#258](https://github.com/colszowka/simplecov/issues/258) and
    [#223](https://github.com/colszowka/simplecov/pull/223) (thanks to @tomykaira)

v0.8.1, 2013-11-10 ([changes](https://github.com/colszowka/simplecov/compare/v0.8.0...v0.8.1))
==================

## Bugfixes

  * Fixed a regression introduced in 0.8.0 - the Forwardable STDLIB module is now required explicitly.
    See [#256](https://github.com/colszowka/simplecov/pull/256) (thanks to @kylev)

v0.8.0, 2013-11-10 ([changes](https://github.com/colszowka/simplecov/compare/v0.7.1...v0.8.0))
==================

**Note: Yanked the same day because of the regression that 0.8.1 fixes, see above**

## TL;DR

It's been way too long since the last official release 0.7.1, but this was partly due to it proving itself
quite stable in most circumstances. This release brings various further stability improvements to result set merging
(especially when working with parallel_tests), the configuration, source file encodings, and command name guessing.

The 0.8 line is the last one to cooperate with Ruby < 1.9. Starting with 0.9, SimpleCov will assume to be running in
Ruby 1.9+, and will not try to detect or bail silently on older Ruby versions. An appropriate deprecation warning
has been added.

## Features

  * Configuration blocks now have access to variables and methods outside of the block's scope.
    See [#238](https://github.com/colszowka/simplecov/pull/238) (thanks to @ms-tg)
  * You can now have a global `~/.simplecov` configuration file.
    See [#195](https://github.com/colszowka/simplecov/pull/195) (thanks to @spagalloco)
  * simplecov-html now uses the MIT-licensed colorbox plugin. Some adjustments when viewing source files,
    including retaining the currently open file on refresh have been added.
    See [simplecov-html #15](https://github.com/colszowka/simplecov-html/pull/15) (thanks to @chetan)
  * Adds support for Rails 4 command guessing, removes default group `vendor/plugins`.
    See [#181](https://github.com/colszowka/simplecov/pull/181) and
    [#203](https://github.com/colszowka/simplecov/pull/203) (thanks to @semanticart and @phallstrom)
  * You can now load simplecov without the default settings by doing `require 'simplecov/no_defaults'`
    or setting `ENV['SIMPLECOV_NO_DEFAULTS']`. Check `simplecov/defaults` to see what preconfigurations are getting
    dropped by using this. See [#209](https://github.com/colszowka/simplecov/pull/209) (thanks to @ileitch)
  * The result set merging now uses the `lockfile` gem to avoid race conditions.
    See [#185](https://github.com/colszowka/simplecov/pull/185) (thanks to @jshraibman-mdsol).
  * Automatically detect the usage of parallel_tests and adjust the command name with the test env number accordingly,
    See [#64](https://github.com/colszowka/simplecov/issues/64) and
    [#185](https://github.com/colszowka/simplecov/pull/185) (thanks to @jshraibman-mdsol).

## Enhancements

  * Rename adapters to "profiles" given that they are bundles of settings. The old adapter methods are
    deprecated, but remain available for now.
    See [#207](https://github.com/colszowka/simplecov/pull/207) (thanks to @mikerobe)
  * Tweaks to the automatic test suite naming. In particular, `rspec/features` should now
    be correctly attributed to RSpec, not Cucumber.
    See [#212](https://github.com/colszowka/simplecov/pull/212) (thanks to @ersatzryan and @betelgeuse)
  * MiniTest should now be identified correctly by the command name guesser.
    See [#244](https://github.com/colszowka/simplecov/pull/244) (thanks to @envygeeks)
  * Makes SimpleCov resilient to inclusion of mathn library.
    See [#175](https://github.com/colszowka/simplecov/pull/175) and
    [#140](https://github.com/colszowka/simplecov/issues/140) (thanks to @scotje)
  * Allow coverage_dir to be an absolute path.
  * See [#190](https://github.com/colszowka/simplecov/pull/190) (thanks to @jshraibman-mdsol)
  * The internal cucumber test suite now uses Capybara 2.
    See [#206](https://github.com/colszowka/simplecov/pull/206) (thanks to @infertux)
  * Work-arounds for the Coverage library shipped in JRuby 1.6 to behave in line with MRI.
    See [#174](https://github.com/colszowka/simplecov/pull/174) (thanks to @grddev)
  * Fix warning: instance variable @exit_status not initialized.
    See [#242](https://github.com/colszowka/simplecov/pull/242) and
    [#213](https://github.com/colszowka/simplecov/pull/213) (thanks to @sferik and @infertux)

## Bugfixes

  * Correct result calculations for people using :nocov: tags.
    See [#215](https://github.com/colszowka/simplecov/pull/215) (thanks to @aokolish)
  * Average hits per line for groups of files is now computed correctly.
    See [#192](http://github.com/colszowka/simplecov/pull/192) and
    [#179](http://github.com/colszowka/simplecov/issues/179) (thanks to @graysonwright)
  * Compatibility with BINARY internal encoding.
    See [#194](https://github.com/colszowka/simplecov/pull/194) and
    [#127](https://github.com/colszowka/simplecov/issues/127) (thanks to @justfalter)
  * Special characters in `SimpleCov.root` are now correctly escaped before being used as a RegExp.
    See [#204](https://github.com/colszowka/simplecov/issues/204) and
    [#237](https://github.com/colszowka/simplecov/pull/237) (thanks to @rli9)

v0.7.1, 2012-10-12 ([changes](https://github.com/colszowka/simplecov/compare/v0.7.0...v0.7.1))
==================

  * [BUGFIX] The gem packages of 0.7.0 (both simplecov and simplecov-html) pushed to Rubygems had some file
    permission issues, leading to problems when installing SimpleCov in a root/system Rubygems install and then
    trying to use it as a normal user (see https://github.com/colszowka/simplecov/issues/171, thanks @envygeeks
    for bringing it up). The gem build process has been changed to always enforce proper permissions before packaging
    to avoid this issue in the future.


v0.7.0, 2012-10-10 ([changes](https://github.com/colszowka/simplecov/compare/v0.6.4...v0.7.0))
==================

  * [FEATURE] The new `maximum_coverage_drop` and `minimum_coverage` now allow you to fail your build when the
    coverage dropped by more than what you allowed or is below a minimum value required. Also, `refuse_coverage_drop` disallows
    any coverage drops between test runs.
    See https://github.com/colszowka/simplecov/pull/151, https://github.com/colszowka/simplecov/issues/11,
    https://github.com/colszowka/simplecov/issues/90, and https://github.com/colszowka/simplecov/issues/96 (thanks to @infertux)
  * [FEATURE] SimpleCov now ships with a built-in MultiFormatter which allows the easy usage of multiple result formatters at
    the same time without the need to write custom wrapper code.
    See https://github.com/colszowka/simplecov/pull/158 (thanks to @nikitug)
  * [BUGFIX] The usage of digits, hyphens and underscores in group names could lead to broken tab navigation
    in the default simplecov-html reports. See https://github.com/colszowka/simplecov-html/pull/14 (thanks to @ebelgarts)
  * [REFACTORING] A few more ruby warnings removed. See https://github.com/colszowka/simplecov/issues/106 and
    https://github.com/colszowka/simplecov/pull/139. (thanks to @lukejahnke)
  * A [Pledgie button](https://github.com/colszowka/simplecov/commit/63cfa99f8658fa5cc66a38c83b3195fdf71b9e93) for those that
    feel generous :)
  * The usual bunch of README fixes and documentation tweaks. Thanks to everyone who contributed those!

v0.6.4, 2012-05-10 ([changes](https://github.com/colszowka/simplecov/compare/v0.6.3...v0.6.4))
==================

  * [BUGFIX] Encoding issues with ISO-8859-encoded source files fixed.
    See https://github.com/colszowka/simplecov/pull/117. (thanks to @Deradon)
  * [BUGFIX] Ensure ZeroDivisionErrors won't occur when calculating the coverage result, which previously
    could happen in certain cases. See https://github.com/colszowka/simplecov/pull/128. (thanks to @japgolly)
  * [REFACTORING] Changed a couple instance variable lookups so SimpleCov does not cause a lot of warnings when
    running ruby at a higher warning level. See https://github.com/colszowka/simplecov/issues/106 and
    https://github.com/colszowka/simplecov/pull/119. (thanks to @mvz and @gioele)


v0.6.3, 2012-05-10 ([changes](https://github.com/colszowka/simplecov/compare/v0.6.2...v0.6.3))
==================

  * [BUGFIX] Modified the API-changes for newer multi_json versions introduced with #122 and v0.6.2 so
    they are backwards-compatible with older multi_json gems in order to avoid simplecov polluting
    the multi_json minimum version requirement for entire applications.
    See https://github.com/colszowka/simplecov/issues/132
  * Added appraisal gem to the test setup in order to run the test suite against both 1.0 and 1.3
    multi_json gems and ensure the above actually works :)

v0.6.2, 2012-04-20 ([changes](https://github.com/colszowka/simplecov/compare/v0.6.1...v0.6.2))
==================

  * [Updated to latest version of MultiJSON and its new API (thanks to @sferik and @ronen).
    See https://github.com/colszowka/simplecov/pull/122

v0.6.1, 2012-02-24 ([changes](https://github.com/colszowka/simplecov/compare/v0.6.0...v0.6.1))
==================

  * [BUGFIX] Don't force-load Railtie on Rails < 3. Fixes regression introduced with
    #83. See https://github.com/colszowka/simplecov/issues/113

v0.6.0, 2012-02-22 ([changes](https://github.com/colszowka/simplecov/compare/v0.5.4...v0.6.0))
==================

  * [FEATURE] Auto-magic `rake simplecov` task for rails
    (see https://github.com/colszowka/simplecov/pull/83, thanks @sunaku)
  * [BUGFIX] Treat source files as UTF-8 to avoid encoding errors
    (see https://github.com/colszowka/simplecov/pull/103, thanks @joeyates)
  * [BUGFIX] Store the invoking terminal command right after loading so they are safe from
    other libraries tampering with ARGV. Among other makes automatic Rails test suite splitting
    (Unit/Functional/Integration) work with recent rake versions again
    (see https://github.com/colszowka/simplecov/issues/110)
  * [FEATURE] If guessing command name from the terminal command fails, try guessing from defined constants
    (see https://github.com/colszowka/simplecov/commit/37afca54ef503c33d888e910f950b3b943cb9a6c)
  * Some refactorings and cleanups as usual. Please refer to the github compare view for a full
    list of changes: https://github.com/colszowka/simplecov/compare/v0.5.4...v0.6.0

v0.5.4, 2011-10-12 ([changes](https://github.com/colszowka/simplecov/compare/v0.5.3...v0.5.4))
==================

  * Do not give exit code 0 when there are exceptions prior to tests
    (see https://github.com/colszowka/simplecov/issues/41, thanks @nbogie)
  * The API for building custom filter classes is now more obvious, using #matches? instead of #passes? too.
    (see https://github.com/colszowka/simplecov/issues/85, thanks @robinroestenburg)
  * Mailers are now part of the Rails adapter as their own group (see
    https://github.com/colszowka/simplecov/issues/79, thanks @geetarista)
  * Removed fix for JRuby 1.6 RC1 float bug because it's been fixed
    (see https://github.com/colszowka/simplecov/issues/86)
  * Readme formatted in Markdown :)

v0.5.3, 2011-09-13 ([changes](https://github.com/colszowka/simplecov/compare/v0.5.2...v0.5.3))
==================

  * Fix for encoding issues that came from the nocov processing mechanism
    (see https://github.com/colszowka/simplecov/issues/71)
  * :nocov: lines are now actually being reflected in the HTML report and are marked in yellow.

  * The Favicon in the HTML report is now determined by the overall coverage and will have the color
    that the coverage percentage gets as a css class to immediately indicate coverage status on first sight.

  * Introduced SimpleCov::SourceFile::Line#status method that returns the coverage status
    as a string for this line - made SimpleCov::HTML use that.
  * Refactored nocov processing and made it configurable using SimpleCov.ncov_token (or it's
    alias SimpleCov.skip_token)

v0.5.2, 2011-09-12 ([changes](https://github.com/colszowka/simplecov/compare/v0.5.1...v0.5.2))
==================

  * Another fix for a bug in JSON processing introduced with MultiJSON in 0.5.1
    (see https://github.com/colszowka/simplecov/pull/75, thanks @sferik)

v0.5.1, 2011-09-12 ([changes](https://github.com/colszowka/simplecov/compare/v0.5.0...v0.5.1))
==================
**Note: Yanked 2011-09-12 because the MultiJSON-patch had a crucial bug**

  * Fix for invalid gemspec dependency string (see https://github.com/colszowka/simplecov/pull/70,
    http://blog.rubygems.org/2011/08/31/shaving-the-yaml-yacc.html, thanks @jspradlin)

  * Added JSON in the form of the multi_json gem as dependency for those cases when built-in JSON
    is unavailable (see https://github.com/colszowka/simplecov/issues/72
    and https://github.com/colszowka/simplecov/pull/74, thanks @sferik)

v0.5.0, 2011-09-09 ([changes](https://github.com/colszowka/simplecov/compare/v0.4.2...v0.5.4))
==================
**Note: Yanked 2011-09-09 because of trouble with the gemspec.**

  * JSON is now used instead of YAML for resultset caching (used for merging). Should resolve
    a lot of problems people used to have because of YAML parser errors.

  * There's a new adapter 'test_frameworks'. Use it outside of Rails to remove `test/`,
    `spec/`, `features/` and `autotest/` dirs from your coverage reports, either directly
    with `SimpleCov.start 'test_frameworks'` or with `SimpleCov.load_adapter 'test_frameworks'`

  * SimpleCov configuration can now be placed centrally in a text file `.simplecov`, which will
    be automatically read on `require 'simplecov'`. This makes using custom configuration like
    groups and filters across your test suites much easier as you only have to specify your config
    once. Just put the whole `SimpleCov.start (...)` code into `APP_ROOT/.simplecov`

  * Lines can now be skipped by using the :nocov: flag in comments that wrap the code that should be
    skipped, like in this example (thanks @phillipkoebbe)

    <pre>
      #:nocov:
      def skipped
        @foo * 2
      end
      #:nocov:
    </pre>

  * Moved file set coverage analytics from simplecov-html to SimpleCov::FileList, a new subclass
    of Array that is always returned for SourceFile lists (i.e. in groups) and can now be used
    in all formatters without the need to roll your own.

  * The exceptions you used to get after removing some code and re-running your tests because SimpleCov
    couldn't find the cached source lines should be resolved (thanks @goneflyin)

  * Coverage strength metric: Average hits/line per source file and result group (thanks @trans)

  * Finally, SimpleCov has an extensive Cucumber test suite

  * Full compatibility with Ruby 1.9.3.preview1

### HTML Formatter:

  * The display of source files has been improved a lot. Weird scrolling trouble, out-of-scope line hit counts
    and such should be a thing of the past. Also, it is prettier now.
  * Source files are now syntax highlighted
  * File paths no longer have that annoying './' in front of them
