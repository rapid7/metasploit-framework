### 3.8.0 / 2018-08-04
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.7.1...v3.8.0)

Enhancements:

* Improve shell escaping used by `RSpec::Core::RakeTask` and `--bisect` so
  that it works on `Pathname` objects. (Andrew Vit, #2479)
* Nicely format errors encountered while loading files specified
  by `--require` option.  (Myron Marston, #2504)
* Significantly improve the performance of `--bisect` on platforms that
  support forking by replacing the shell-based runner with one that uses
  forking so that RSpec and the application environment can be booted only
  once, instead of once per spec run. (Myron Marston, #2511)
* Provide a configuration API to pick which bisect runner is used for
  `--bisect`. Pick a runner via `config.bisect_runner = :shell` or
  `config.bisect_runner = :fork` in a file loaded by a `--require`
  option passed at the command line or set in `.rspec`. (Myron Marston, #2511)
* Support the [XDG Base Directory
  Specification](https://specifications.freedesktop.org/basedir-spec/latest/)
  for the global options file. `~/.rspec` is still supported when no
  options file is found in `$XDG_CONFIG_HOME/rspec/options` (Magnus Bergmark, #2538)
* Extract `RSpec.world.prepare_example_filtering` that sets up the
  example filtering for custom RSpec runners. (Oleg Pudeyev, #2552)

Bug Fixes:

* Prevent an `ArgumentError` when truncating backtraces with two identical
  backtraces. (Systho, #2515, Benoit Tigeot, #2539)

### 3.7.1 / 2018-01-02
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.7.0...v3.7.1)

Bug Fixes:

* Work around duplicate config hook regression introduced
  by Ruby 2.5's lazy proc allocation. (Myron Marston, #2497)

### 3.7.0 / 2017-10-17
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.6.0...v3.7.0)

Enhancements:

* Add `-n` alias for `--next-failure`. (Ian Ker-Seymer, #2434)
* Improve compatibility with `--enable-frozen-string-literal` option
  on Ruby 2.3+. (Pat Allan, #2425, #2427, #2437)
* Do not run `:context` hooks for example groups that have been skipped.
  (Devon Estes, #2442)
* Add `errors_outside_of_examples_count` to the JSON formatter.
  (Takeshi Arabiki, #2448)

Bug Fixes:

* Improve compatibility with frozen string literal flag. (#2425, Pat Allan)

### 3.6.0 / 2017-05-04
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.6.0.beta2...v3.6.0)

Enhancements:

* Add seed information to JSON formatter output. (#2388, Mitsutaka Mimura)
* Include example id in the JSON formatter output. (#2369, Xavier Shay)
* Respect changes to `config.output_stream` after formatters have been
  setup. (#2401, #2419, Ilya Lavrov)

Bug Fixes:

* Delay formatter loading until the last minute to allow accessing the reporter
  without triggering formatter setup. (Jon Rowe, #2243)
* Ensure context hook failures running before an example can access the
  reporter. (Jon Jensen, #2387)
* Multiple fixes to allow using the runner multiple times within the same
  process: `RSpec.clear_examples` resets the formatter and no longer clears
  shared examples, and streams can be used across multiple runs rather than
  being closed after the first. (#2368, Xavier Shay)
* Prevent unexpected `example_group_finished` notifications causing an error.
  (#2396, VTJamie)
* Fix bugs where `config.when_first_matching_example_defined` hooks would fire
  multiple times in some cases. (Yuji Nakayama, #2400)
* Default `last_run_status` to "unknown" when the `status` field in the
  persistence file contains an unrecognized value. (#2360, matrinox)
* Prevent `let` from defining an `initialize` method. (#2414, Jon Rowe)

### 3.6.0.beta2 / 2016-12-12
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.6.0.beta1...v3.6.0.beta2)

Enhancements:

* Include count of errors occurring outside examples in default summaries.
  (#2351, Jon Rowe)
* Warn when including shared example groups recursively. (#2356, Jon Rowe)
* Improve failure snippet syntax highlighting with CodeRay to highlight
  RSpec "keywords" like `expect`. (#2358, Myron Marston)

### 3.6.0.beta1 / 2016-10-09
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.4...v3.6.0.beta1)

Enhancements:

* Warn when duplicate shared examples definitions are loaded due to being
  defined in files matching the spec pattern (e.g. `_spec.rb`) (#2278, Devon Estes)
* Improve metadata filtering so that it can match against any object
  that implements `===` instead of treating regular expressions as
  special. (Myron Marston, #2294)
* Improve `rspec -v` so that it prints out the versions of each part of
  RSpec to prevent confusion. (Myron Marston, #2304)
* Add `config.fail_if_no_examples` option which causes RSpec to fail if
  no examples are found. (Ewa Czechowska, #2302)
* Nicely format errors encountered while loading spec files.
  (Myron Marston, #2323)
* Improve the API for enabling and disabling color output (Josh
  Justice, #2321):
  * Automatically enable color if the output is a TTY, since color is
    nearly always desirable if the output can handle it.
  * Introduce new CLI flag to force color on (`--force-color`), even
    if the output is not a TTY. `--no-color` continues to work as well.
  * Introduce `config.color_mode` for configuring the color from Ruby.
    `:automatic` is the default and will produce color if the output is
    a TTY. `:on` forces it on and `:off` forces it off.

### 3.5.4 / 2016-09-30
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.3...v3.5.4)

Bug Fixes:

* Remove accumulated `ExampleGroup` constants when reseting RSpec,
  preventing a memory leak. (TravisSpangle, #2328)

### 3.5.3 / 2016-09-02
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.2...v3.5.3)

Bug Fixes:

* When applying shared group metadata to a host group, overwrite
  conflicting keys if the value in the host group was inherited from
  a parent group instead of being specified at that level.
  (Myron Marston, #2307)
* Handle errors in `:suite` hooks and provide the same nicely formatted
  output as errors that happen in examples. (Myron Marston, #2316)
* Set the exit status to non-zero when an error occurs in an
  `after(:context)` hook. (Myron Marston, #2320)

### 3.5.2 / 2016-07-28
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.1...v3.5.2)

Bug Fixes:

* Wait to report `example_finished` until the example's `execution_result`
  has been completely filled in. (Myron Marston, #2291)
* Make sure example block is still available when using `duplicate_with`
  to clone examples. (bootstraponline, #2298)
* Don't include the default `--pattern` in the Rake task when
  `rspec_opts` specifies its own. (Jon Rowe, #2305)

### 3.5.1 / 2016-07-06
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.0...v3.5.1)

Bug Fixes:

* Ensure that config hooks that are added to existing example groups are
  added only once. (Eugene Kenny, #2280)

### 3.5.0 / 2016-07-01
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.0.beta4...v3.5.0)

Enhancements:

* Include any `SPEC_OPTS` in reproduction command printed at the end of
  a bisect run. (Simon Coffey, #2274)

Bug Fixes:

* Handle `--bisect` in `SPEC_OPTS` environment variable correctly so as
  to avoid infinite recursion. (Simon Coffey, #2271)

### 3.5.0.beta4 / 2016-06-05
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.0.beta3...v3.5.0.beta4)

Enhancements:

* Filter out bundler stackframes from backtraces by default, since
  Bundler 1.12 now includes its own frames in stack traces produced
  by using `bundle exec`. (Myron Marston, #2240)
* HTML Formatter uses exception presenter to get failure message
  for consistency with other formatters. (@mrageh, #2222)
* Load spec files in the order of the directories or files passed
  at the command line, making it easy to make some specs run before
  others in a one-off manner.  For example, `rspec spec/unit
  spec/acceptance --order defined` will run unit specs before acceptance
  specs. (Myron Marston, #2253)
* Add new `config.include_context` API for configuring global or
  filtered inclusion of shared contexts in example groups.
  (Myron Marston, #2256)
* Add new `config.shared_context_metadata_behavior = :apply_to_host_groups`
  option, which causes shared context metadata to be inherited by the
  metadata hash of all host groups and examples instead of configuring
  implicit auto-inclusion based on the passed metadata. (Myron Marston, #2256)

Bug Fixes:

* Fix `--bisect` so it works on large spec suites that were previously triggering
  "Argument list too long errors" due to all the spec locations being passed as
  CLI args. (Matt Jones, #2223).
* Fix deprecated `:example_group`-based filtering so that it properly
  applies to matching example groups. (Myron Marston, #2234)
* Fix `NoMethodError` caused by Java backtraces on JRuby. (Michele Piccirillo, #2244)

### 3.5.0.beta3 / 2016-04-02
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.0.beta2...v3.5.0.beta3)

Enhancements:

* Add new `config.filter_run_when_matching` API, intended to replace
  the combination of `config.filter_run` and
  `config.run_all_when_everything_filtered` (Myron Marston, #2206)

Bug Fixes:

* Use the encoded string logic for source extraction. (Jon Rowe, #2183)
* Fix rounding issue in duration formatting helper. (Fabersky, Jon Rowe, #2208)
* Fix failure snippet extraction so that `def-end` snippets
  ending with `end`-only line can be extracted properly.
  (Yuji Nakayama, #2215)

### 3.5.0.beta2 / 2016-03-10
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.5.0.beta1...v3.5.0.beta2)

Enhancements:

* Remove unneeded `:execution_result` example group metadata, saving a
  bit of memory. (Myron Marston, #2172)
* Apply hooks registered with `config` to previously defined groups.
  (Myron Marston, #2189)
* `RSpec::Core::Configuration#reporter` is now public API under SemVer.
  (Jon Rowe, #2193)
* Add new `config.when_first_matching_example_defined` hook. (Myron
  Marston, #2175)

### 3.5.0.beta1 / 2016-02-06
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.4.4...v3.5.0.beta1)

Enhancements:

* Add `RSpec::Core::ExampleGroup.currently_executing_a_context_hook?`,
  primarily for use by rspec-rails. (Sam Phippen, #2131)

Bug Fixes:

* Ensure `MultipleExceptionError` does not contain a recursive reference
  to itself. (Sam Phippen, #2133)

### 3.4.4 / 2016-03-09
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.4.3...v3.4.4)

Bug Fixes:

* Fix `RSpec::Core::RakeTask` so that it works with Rake 11.
  (Travis Grathwell, #2197)

### 3.4.3 / 2016-02-19
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.4.2...v3.4.3)

Bug Fixes:

* Prevent a `TypeError` from occurring when running via the rake task when
  Ruby crashes. (Patrik Wenger, #2161)
* Only consider example and group declaration lines from a specific file
  when applying line number filtering, instead of considering all
  declaration lines from all spec files. (Myron Marston, #2170)
* Fix failure snippet extraction so that snippets that contain `do-end` style
  block and end with `end`-only line can be extracted properly.
  (Yuji Nakayama, #2173)
* Prevent infinite recursion when an exception is caused by itself.
  (Jon Rowe, #2128)

### 3.4.2 / 2016-01-26
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.4.1...v3.4.2)

Bug Fixes:

* Fix `rspec --profile` when an example calls `abort` or `exit`.
  (Bradley Schaefer, #2144)
* Fix `--drb` so that when no DRb server is running, it prevents
  the DRb connection error from being listed as the cause of all
  expectation failures. (Myron Marston, #2156)
* Fix syntax highlighter so that it works when the `coderay` gem is
  installed as a rubygem but not already available on your load path
  (as happens when you use bundler). (Myron Marston, #2159)

### 3.4.1 / 2015-11-18
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.4.0...v3.4.1)

Bug Fixes:

* Fix backtrace formatter to handle backtraces that are `nil`.
  (Myron Marston, #2118)

### 3.4.0 / 2015-11-11
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.3.2...v3.4.0)

Enhancements:

* Combine multiple `--pattern` arguments making them equivalent to
  `--pattern=1,2,...,n`. (Jon Rowe, #2002)
* Improve `inspect` and `to_s` output for `RSpec::Core::Example`
  objects, replacing Ruby's excessively verbose output. (Gavin Miller, #1922)
* Add `silence_filter_announcements` configuration option.
  (David Raffensperger, #2007)
* Add optional `example_finished` notification to the reporter protocol for
  when you don't care about the example outcome. (Jon Rowe, #2013)
* Switch `--bisect` to a recursion-based bisection algorithm rather than
  a permutation-based one. This better handles cases where an example
  depends upon multiple other examples instead of just one and minimizes
  the number of runs necessary to determine that an example set cannot be
  minimized further. (Simon Coffey, #1997)
* Allow simple filters (e.g. `:symbol` key only) to be triggered by truthey
  values. (Tim Mertens, #2035)
* Remove unneeded warning about need for `ansicon` on Windows when using
  RSpec's `--color` option. (Ashley Engelund, #2038)
* Add option to configure RSpec to raise errors when issuing warnings.
  (Jon Rowe, #2052)
* Append the root `cause` of a failure or error to the printed failure
  output when a `cause` is available. (Adam Magan)
* Stop rescuing `NoMemoryError`, `SignalExcepetion`, `Interrupt` and
  `SystemExit`. It is dangerous to interfere with these. (Myron Marston, #2063)
* Add `config.project_source_dirs` setting which RSpec uses to determine
  if a backtrace line comes from your project source or from some
  external library. It defaults to `spec`, `lib` and `app` but can be
  configured differently. (Myron Marston, #2088)
* Improve failure line detection so that it looks for the failure line
  in any project source directory instead of just in the spec file.
  In addition, if no backtrace lines can be found from a project source
  file, we fall back to displaying the source of the first backtrace
  line. This should virtually eliminate the "Unable to find matching
  line from backtrace" messages. (Myron Marston, #2088)
* Add support for `:extra_failure_lines` example metadata that will
  be appended to the failure output. (bootstraponline, #2092).
* Add `RSpec::Core::Example#duplicate_with` to produce new examples
  with cloned metadata. (bootstraponline, #2098)
* Add `RSpec::Core::Configuration#on_example_group_definition` to register
  hooks to be invoked when example groups are created. (bootstraponline, #2094)
* Add `add_example` and `remove_example` to `RSpec::Core::ExampleGroup` to
  allow  manipulating an example groups examples. (bootstraponline, #2095)
* Display multiline failure source lines in failure output when Ripper is
  available (MRI >= 1.9.2, and JRuby >= 1.7.5 && < 9.0.0.0.rc1).
  (Yuji Nakayama, #2083)
* Add `max_displayed_failure_line_count` configuration option
  (defaults to 10). (Yuji Nakayama, #2083)
* Enhance `fail_fast` option so it can take a number (e.g. `--fail-fast=3`)
  to force the run to abort after the specified number of failures.
  (Jack Scotti, #2065)
* Syntax highlight the failure snippets in text formatters when `color`
  is enabled and the `coderay` gem is installed on a POSIX system.
  (Myron Marston, #2109)

Bug Fixes:

* Lock `example_status_persistence_file` when reading from and writing
  to it to prevent race conditions when multiple processes try to use
  it. (Ben Woosley, #2029)
* Fix regression in 3.3 that caused spec file names with square brackets in
  them (such as `1[]_spec.rb`) to not be loaded properly. (Myron Marston, #2041)
* Fix output encoding issue caused by ASCII literal on 1.9.3 (Jon Rowe, #2072)
* Fix requires in `rspec/core/rake_task.rb` to avoid double requires
  seen by some users. (Myron Marston, #2101)

### 3.3.2 / 2015-07-15
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.3.1...v3.3.2)

Bug Fixes:

* Fix formatters to handle exceptions for which `backtrace` returns `nil`.
  (Myron Marston, #2023)
* Fix duplicate formatter detection so that it allows subclasses of formatters
  to be added. (Sebastián Tello, #2019)

### 3.3.1 / 2015-06-18
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.3.0...v3.3.1)

Bug Fixes:

* Correctly run `before(:suite)` (and friends) in the context of an example
  group instance, thus making the expected RSpec environment available.
  (Jon Rowe, #1986)

### 3.3.0 / 2015-06-12
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.2.3...v3.3.0)

Enhancements:

* Expose the reporter used to run examples via `RSpec::Core::Example#reporter`.
  (Jon Rowe, #1866)
* Make `RSpec::Core::Reporter#message` a public supported API. (Jon Rowe, #1866)
* Allow custom formatter events to be published via
  `RSpec::Core::Reporter#publish(event_name, hash_of_attributes)`. (Jon Rowe, #1869)
* Remove dependency on the standard library `Set` and replace with `RSpec::Core::Set`.
  (Jon Rowe, #1870)
* Assign a unique id to each example and group so that they can be
  uniquely identified, even for shared examples (and similar situations)
  where the location isn't unique. (Myron Marston, #1884)
* Use the example id in the rerun command printed for failed examples
  when the location is not unique. (Myron Marston, #1884)
* Add `config.example_status_persistence_file_path` option, which is
  used to persist the last run status of each example. (Myron Marston, #1888)
* Add `:last_run_status` metadata to each example, which indicates what
  happened the last time an example ran. (Myron Marston, #1888)
* Add `--only-failures` CLI option which filters to only the examples
  that failed the last time they ran. (Myron Marston, #1888)
* Add `--next-failure` CLI option which allows you to repeatedly focus
  on just one of the currently failing examples, then move on to the
  next failure, etc. (Myron Marston, #1888)
* Make `--order random` ordering stable, so that when you rerun a
  subset with a given seed, the examples will be order consistently
  relative to each other. (Myron Marston, #1908)
* Set example group constant earlier so errors when evaluating the context
  include the example group name (Myron Marson, #1911)
* Make `let` and `subject` threadsafe. (Josh Cheek, #1858)
* Add version information into the JSON formatter. (Mark Swinson, #1883)
* Add `--bisect` CLI option, which will repeatedly run your suite in
  order to isolate the failures to the smallest reproducible case.
  (Myron Marston, #1917)
* For `config.include`, `config.extend` and `config.prepend`, apply the
  module to previously defined matching example groups. (Eugene Kenny, #1935)
* When invalid options are parsed, notify users where they came from
  (e.g. `.rspec` or `~/.rspec` or `ENV['SPEC_OPTS']`) so they can
  easily find the source of the problem. (Myron Marston, #1940)
* Add pending message contents to the json formatter output. (Jon Rowe, #1949)
* Add shared group backtrace to the output displayed by the built-in
  formatters for pending examples that have been fixed. (Myron Marston, #1946)
* Add support for `:aggregate_failures` metadata. Tag an example or
  group with this metadata and it'll use rspec-expectations'
  `aggregate_failures` feature to allow multiple failures in an example
  and list them all, rather than aborting on the first failure. (Myron
  Marston, #1946)
* When no formatter implements #message add a fallback to prevent those
  messages being lost. (Jon Rowe, #1980)
* Profiling examples now takes into account time spent in `before(:context)`
  hooks. (Denis Laliberté, Jon Rowe, #1971)
* Improve failure output when an example has multiple exceptions, such
  as one from an `it` block and one from an `after` block. (Myron Marston, #1985)

Bug Fixes:

* Handle invalid UTF-8 strings within exception methods. (Benjamin Fleischer, #1760)
* Fix Rake Task quoting of file names with quotes to work properly on
  Windows. (Myron Marston, #1887)
* Fix `RSpec::Core::RakeTask#failure_message` so that it gets printed
  when the task failed. (Myron Marston, #1905)
* Make `let` work properly when defined in a shared context that is applied
  to an individual example via metadata. (Myron Marston, #1912)
* Ensure `rspec/autorun` respects configuration defaults. (Jon Rowe, #1933)
* Prevent modules overriding example group defined methods when included,
  prepended or extended by config defined after an example group. (Eugene Kenny, #1935)
* Fix regression which caused shared examples to be mistakenly run when specs
  where filtered to a particular location.  (Ben Axnick, #1963)
* Fix time formatting logic so that it displays 70 seconds as "1 minute,
  10 seconds" rather than "1 minute, 1 second". (Paul Brennan, #1984)
* Fix regression where the formatter loader would allow duplicate formatters.
  (Jon Rowe, #1990)

### 3.2.3 / 2015-04-06
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.2.2...v3.2.3)

Bug Fixes:

* Fix how the DSL methods are defined so that RSpec is compatible with
  gems that define methods of the same name on `Kernel` (such as
  the `its-it` gem). (Alex Kwiatkowski, Ryan Ong, #1907)
* Fix `before(:context) { skip }` so that it does not wrongly cause the
  spec suite to exit with a non-zero status when no examples failed.
  (Myron Marston, #1926)

### 3.2.2 / 2015-03-11
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.2.1...v3.2.2)

Bug Fixes:

* Fix regression in 3.2.0 that allowed tag-filtered examples to
  run even if there was a location filter applied to the spec
  file that was intended to limit the file to other examples.
  (#1894, Myron Marston)

### 3.2.1 / 2015-02-23
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.2.0...v3.2.1)

Bug Fixes:

* Notify start-of-run seed _before_ `start` notification rather than
  _after_ so that formatters like Fuubar work properly. (Samuel Esposito, #1882)

### 3.2.0 / 2015-02-03
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.7...v3.2.0)

Enhancements:

* Improve the `inspect` output of example groups. (Mike Dalton, #1687)
* When rake task fails, only output the command if `verbose` flag is
  set. (Ben Snape, #1704)
* Add `RSpec.clear_examples` as a clear way to reset examples in between
  spec runs, whilst retaining user configuration.  (Alexey Fedorov, #1706)
* Reduce string allocations when defining and running examples by 70%
  and 50% respectively. (Myron Marston, #1738)
* Removed dependency on pathname from stdlib. (Sam Phippen, #1703)
* Improve the message presented when a user hits Ctrl-C.
  (Alex Chaffee #1717, #1742)
* Improve shared example group inclusion backtrace displayed
  in failed example output so that it works for all methods
  of including shared example groups and shows all inclusion
  locations. (Myron Marston, #1763)
* Issue seed notification at start (as well as the end) of the reporter
  run. (Arlandis Word, #1761)
* Improve the documentation of around hooks. (Jim Kingdon, #1772)
* Support prepending of modules into example groups from config and allow
  filtering based on metadata. (Arlandis Word, #1806)
* Emit warnings when `:suite` hooks are registered on an example group
  (where it has always been ignored) or are registered with metadata
  (which has always been ignored). (Myron Marston, #1805)
* Provide a friendly error message when users call RSpec example group
  APIs (e.g. `context`, `describe`, `it`, `let`, `before`, etc) from
  within an example where those APIs are unavailable. (Myron Marston, #1819)
* Provide a friendly error message when users call RSpec example
  APIs (e.g. `expect`, `double`, `stub_const`, etc) from
  within an example group where those APIs are unavailable.
  (Myron Marston, #1819)
* Add new `RSpec::Core::Sandbox.sandboxed { }` API that facilitates
  testing RSpec with RSpec, allowing you to define example groups
  and example from within an example without affecting the global
  `RSpec.world` state. (Tyler Ball, 1808)
* Apply line-number filters only to the files they are scoped to,
  allowing you to mix filtered and unfiltered files. (Myron Marston, #1839)
* When dumping pending examples, include the failure details so that you
  don't have to un-pend the example to see it. (Myron Marston, #1844)
* Make `-I` option support multiple values when separated by
  `File::PATH_SEPARATOR`, such as `rspec -I foo:bar`. This matches
  the behavior of Ruby's `-I` option. (Fumiaki Matsushima, #1855).
* Treat each example as having a singleton example group for the
  purposes of applying metadata-based features that normally apply
  to example groups to individually tagged examples. For example,
  `RSpec.shared_context "Uses redis", :uses_redis` will now apply
  to individual examples tagged with `:uses_redis`, as will
  `config.include RedisHelpers, :uses_redis`, and
  `config.before(:context, :uses_redis) { }`, etc. (Myron Marston, #1749)

Bug Fixes:

* When assigning generated example descriptions, surface errors
  raised by `matcher.description` in the example description.
  (Myron Marston, #1771)
* Don't consider expectations from `after` hooks when generating
  example descriptions. (Myron Marston, #1771)
* Don't apply metadata-filtered config hooks to examples in groups
  with matching metadata when those examples override the parent
  metadata value to not match. (Myron Marston, #1796)
* Fix `config.expect_with :minitest` so that `skip` uses RSpec's
  implementation rather than Minitest's. (Jonathan Rochkind, #1822)
* Fix `NameError` caused when duplicate example group aliases are defined and
  the DSL is not globally exposed. (Aaron Kromer, #1825)
* When a shared example defined in an external file fails, use the host
  example group (from a loaded spec file) for the re-run command to
  ensure the command will actually work. (Myron Marston, #1835)
* Fix location filtering to work properly for examples defined in
  a nested example group within a shared example group defined in
  an external file. (Bradley Schaefer, Xavier Shay, Myron Marston, #1837)
* When a pending example fails (as expected) due to a mock expectation,
  set `RSpec::Core::Example::ExecutionResult#pending_exception` --
  previously it was not being set but should have been. (Myron Marston, #1844)
* Fix rake task to work when `rspec-core` is installed in a directory
  containing a space. (Guido Günther, #1845)
* Fix regression in 3.1 that caused `describe Regexp` to raise errors.
  (Durran Jordan, #1853)
* Fix regression in 3.x that caused the profile information to be printed
  after the summary. (Max Lincoln, #1857)
* Apply `--seed` before loading `--require` files so that required files
  can access the provided seed. (Myron Marston, #1745)
* Handle `RSpec::Core::Formatters::DeprecationFormatter::FileStream` being
  reopened with an IO stream, which sometimes happens with spring.
  (Kevin Mook, #1757)

### 3.1.7 / 2014-10-11
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.6...v3.1.7)

Bug Fixes:

* Fix `Metadata.relative_path` so that for a current directory of
  `/foo/bar`, `/foo/bar_1` is not wrongly converted to `._1`.
  (Akos Vandra, #1730)
* Prevent constant lookup mistakenly finding `RSpec::ExampleGroups` generated
  constants on 1.9.2 by appending a trailing `_` to the generated names.
  (Jon Rowe, #1737)
* Fix bug in `:pending` metadata. If it got set in any way besides passing
  it as part of the metadata literal passed to `it` (such as by using
  `define_derived_metadata`), it did not have the desired effect,
  instead marking the example as `:passed`. (Myron Marston, #1739)

### 3.1.6 / 2014-10-08
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.5...v3.1.6)

Bug Fixes:

* Fix regression in rake task pattern handling, that prevented patterns
  that were relative from the current directory rather than from `spec`
  from working properly. (Myron Marston, #1734)
* Prevent rake task from generating duplicate load path entries.
  (Myron Marston, #1735)

### 3.1.5 / 2014-09-29
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.4...v3.1.5)

Bug Fixes:

* Fix issue with the rake task incorrectly escaping strings on Windows.
  (Jon Rowe #1718)
* Support absolute path patterns. While this wasn't officially supported
  previously, setting `rake_task.pattern` to an absolute path pattern in
  RSpec 3.0 and before worked since it delegated to `FileList` internally
  (but now just forwards the pattern on to the `rspec` command).
  (Myron Marston, #1726)

### 3.1.4 / 2014-09-18
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.3...v3.1.4)

Bug Fixes:

* Fix implicit `subject` when using `describe false` or `describe nil`
  so that it returns the provided primitive rather than the string
  representation. (Myron Marston, #1710)
* Fix backtrace filtering to allow code in subdirectories of your
  current working directory (such as vendor/bundle/...) to be filtered
  from backtraces. (Myron Marston, #1708)

### 3.1.3 / 2014-09-15
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.2...v3.1.3)

Bug Fixes:

* Fix yet another regression in rake task pattern handling, to allow
  `task.pattern = FileList["..."]` to work. That was never intended
  to be supported but accidentally worked in 3.0 and earlier.
  (Myron Marston, #1701)
* Fix pattern handling so that files are normalized to absolute paths
  before subtracting the `--exclude-pattern` matched files from the
  `--pattern` matched files so that it still works even if the patterns
  are in slightly different forms (e.g. one starting with `./`).
  (Christian Nelson, #1698)

### 3.1.2 / 2014-09-08
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.1...v3.1.2)

Bug Fixes:

* Fix another regression in rake task pattern handling, so that patterns
  that start with `./` still work. (Christian Nelson, #1696)

### 3.1.1 / 2014-09-05
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.1.0...v3.1.1)

Bug Fixes:

* Fix a regression in rake task pattern handling, so that `rake_task.pattern = array`
  works again. While we never intended to support array values (or even knew that worked!),
  the implementation from 3.0 and earlier used `FileList` internally, which allows arrays.
  The fix restores the old behavior. (Myron Marston, #1694)

### 3.1.0 / 2014-09-04
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.4...v3.1.0)

Enhancements:

* Update files generated by `rspec --init` so that warnings are enabled
  in commented out section of `spec_helper` rather than `.rspec` so users
  have to consciously opt-in to the setting. (Andrew Hooker, #1572)
* Update `spec_helper` generated by `rspec --init` so that it sets the new
  rspec-expectations `include_chain_clauses_in_custom_matcher_descriptions`
  config option (which will be on by default in RSpec 4) and also sets the
  rspec-mocks `verify_partial_doubles` option (which will also default
  to on in RSpec 4). (Myron Marston, #1647)
* Provide an `inspect` output for example procsy objects (used in around
  hooks) that doesn't make them look like procs. (Jon Rowe, #1620)
* Remove a few unneeded `require` statements from
  `rspec/core/rake_task.rb`, making it even more lighterweight.
  (Myron Marston, #1640)
* Allow rspec-core to be used when neither rspec-mocks or
  rspec-expectations are installed, without requiring any
  user configuration. (Sam Phippen, Myron Marston, #1615)
* Don't filter out gems from backtraces by default. (The RSpec
  gems will still be filtered). User feedback has indicated
  that including gems in default backtraces will be useful.
  (Myron Marston, #1641)
* Add new `config.filter_gems_from_backtrace "rack", "rake"` API
  to easily filter the named gems from backtraces. (Myron Marston, #1682)
* Fix default backtrace filters so that the RSpec binary is
  excluded when installing RSpec as a bundler `:git` dependency.
  (Myron Marston, #1648)
* Simplify command generated by the rake task so that it no longer
  includes unnecessary `-S`. (Myron Marston, #1559)
* Add `--exclude-pattern` CLI option, `config.exclude_pattern =` config
  option and `task.exclude_pattern =` rake task config option. Matching
  files will be excluded. (John Gesimondo, Myron Marston, #1651, #1671)
* When an around hook fails to execute the example, mark it as
  pending (rather than passing) so the user is made aware of the
  fact that the example did not actually run. (Myron Marston, #1660)
* Remove dependency on `FileUtils` from the standard library so that users do
  not get false positives where their code relies on it but they are not
  requiring it. (Sam Phippen, #1565)

Bug Fixes:

* Fix rake task `t.pattern =` option so that it does not run all specs
  when it matches no files, by passing along a `--pattern` option to
  the `rspec` command, rather than resolving the file list and passing
  along the files individually. (Evgeny Zislis, #1653)
* Fix rake task default pattern so that it follows symlinks properly.
  (Myron Marston, #1672)
* Fix default pattern used with `rspec` command so that it follows
  symlinks properly. (Myron Marston, #1672)
* Change how we assign constant names to example group classes so that
  it avoids a problem with `describe "Core"`. (Daniela Wellisz, #1679)
* Handle rendering exceptions that have a different encoding than that
  of their original source file. (Jon Rowe, #1681)
* Allow access to message_lines without colour for failed examples even
  when they're part of a shared example group. (tomykaira, #1689)

### 3.0.4 / 2014-08-14
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.3...v3.0.4)

Bug Fixes:

* Fix processing order of CLI options so that if `config.files_to_run`
  is accessed from a file loaded by `--require`, `--pattern` is still
  applied. (Myron Marston, #1652)
* Fix `config.pattern=` so that it still takes affect even if
  `config.files_to_run` has already been accessed. (Myron Marston, #1652)

### 3.0.3 / 2014-07-21
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.2...v3.0.3)

Bug Fixes:

* Properly convert both parts of a description into strings before
  concatenation.  (@nicklink483, #1636)
* Exclude the working directory when figuring out folders to ignore.
  (Jon Rowe, Myron Marston, #1616)
* Allow `::RSpec::Core::Notifications::FailedExampleNotification#message_lines`
  to be accessed without a colouriser. (@tomykaira, #1637)

### 3.0.2 / 2014-06-19
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.1...v3.0.2)

Bug Fixes:

* Fix regression in CLI option handling that prevented `--tag slow`
  passed at the command line from overriding `--tag ~slow` in `.rspec`.
  (Colin Jones, #1602)
* Fix metadata `:example_group` deprecation warning so that it gets
  issued at the call site of the configuration that specified it as
  a filter rather than later when an example group is defined.
  (Myron Marston, #1562)
* Make the line that is printed when a shared example group fails indicating
  where the concrete example group is white, separating it from the stack trace
  that is produced for the failure. (Sam Phippen, Jon Rowe, #1606)

### 3.0.1 / 2014-06-12
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.0...v3.0.1)

Bug Fixes:

* Fix a couple ruby warnings caused by rspec-core when loaded.
  (Prem Sichanugrist, #1584)
* Example groups named `Config` will no longer cause a Ruby warning to be
  issued. (Jimmy Cuadra, #1580)

### 3.0.0 / 2014-06-01
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.0.rc1...v3.0.0)

Bug Fixes:

* Fix `BaseTextFormatter` so that it does not re-close a closed output
  stream. (Myron Marston)
* Fix regression in metadata that caused the metadata hash of a top-level
  example group to have a `:parent_example_group` key even though it has
  no parent example group. (Myron Marston)

Enhancements:

* Alter the default `spec_helper.rb` to no longer recommend
  `config.full_backtrace = true` see #1536 for discussion. (Jon Rowe)

### 3.0.0.rc1 / 2014-05-18
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.0.beta2...v3.0.0.rc1)

Breaking Changes for 3.0.0:

* Change `described_class` so that in a nested group like `describe
  MyClass`, it returns `MyClass` rather than the outer group's described
  class. (Myron Marston)
* Refactor filter manager so that it no longer subclasses Hash and has a
  tighter, more domain-specific interface. (Sergey Pchelincev)
* Remove legacy colours definitions from `BaseTextFormatter`. (Jon Rowe)
* Remove console color definitions from `BaseTextFormatter`. (Jon Rowe)
* Restructure example group metadata so that the computed keys are
  exposed directly off of the metadata hash rather than being on
  a nested `:example_group` subhash. In addition, the parent example
  group metadata is now available as `[:parent_example_group]` rather
  than `[:example_group][:example_group]`. Deprecated access via the
  old key structure is still provided. (Myron Marston)
* Remove `:describes` metadata key. It duplicates `:described_class`
  for no good reason. Deprecated access via `:describes` is still
  provided. (Myron Marston)
* Rename `:example_group_block` metadata key to `:block`.
  (Myron Marston)
* Remove deprecated `RSpec::Core::Example#options`. (Myron Marston)
* Move `BaseTextFormatter#colorize_summary` to `SummaryNotification#colorize_with`
  (Jon Rowe).
* `describe some_hash` treated `some_hash` as metadata in RSpec 2.x but
  will treat it as the described object in RSpec 3.0. Metadata must
  always come after the description args. (Myron Marston)
* Remove deprecated `display_name` alias of `ExampleGroup.description`.
  (Myron Marston)
* Remove deprecated `describes` alias of `ExampleGroup.described_class`.
  (Myron Marston)
* Remove deprecated `RSpec::Core::ExampleGroup.alias_it_behaves_like_to`.
  Use `RSpec::Core::Configuration#alias_it_behaves_like_to` instead.
  (Myron Marston)
* Remove deprecated `RSpec::Core::ExampleGroup.alias_example_to`.
  Use `RSpec::Core::Configuration#alias_example_to` instead.
  (Myron Marston)
* Removed `focused` example alias and change example/group aliases
  `fit`, `focus`, `fcontext` and `fdescribe` to no longer include
  `:focused => true` metadata. They only contain `:focus => true`
  metadata now. This means that you will need to filter them with
  `filter_run :focus`, not `filter_run :focused`. (Myron Marston)
* Remove `--line-number` filtering. It's semantically dubious since it's
  a global filter (potentially applied to multiple files) but there's no
  meaningful connection between the same line number in multiple files.
  Instead use the `rspec path/to/spec.rb:23:46` form, which is terser
  and makes more sense as it is scoped to a file. (Myron Marston)
* Remove `--default_path` as an alias for `--default-path`. (Jon Rowe)
* Remove deprecated `share_examples_for`. There's still
  `shared_examples` and `shared_examples_for`. (Myron Marston)
* Rename `RSpec::Core::Configuration#warnings` to
  `RSpec::Core::Configuration#warnings?` since it's a boolean flag.
  (Myron Marston)
* RSpec's global state is no longer reset after a spec run. This gives
  more flexibility to alternate runners to decide when and if they
  want the state reset. Alternate runners are now responsible for
  calling this (or doing a similar reset) if they are going to run
  the spec suite multiple times in the same process. (Sam Phippen)
* Merge `RSpec::Core::CommandLine` (never formally declared public)
  into `RSpec::Core::Runner`. (Myron Marston)
* Remove `color_enabled` as an alias of `color`. (Jon Rowe)
* Remove `backtrace_cleaner` as an alias of `backtrace_formatter`. (Jon Rowe)
* Remove `filename_pattern` as an alias of `pattern`. (Jon Rowe)
* Extract support for legacy formatters to `rspec-legacy_formatters`. (Jon Rowe)
* `RSpec::Configuration#formatters` now returns a dup to prevent mutation. (Jon Rowe)
* Replace `stdlib` as an available expectation framework with `test_unit` and
  `minitest`. (Aaron Kromer)
* Remove backtrace formatting helpers from `BaseTextFormatter`. (Jon Rowe)
* Extract profiler support to `ProfileFormatter` and `ProfileNotification`.
  Formatters should implement `dump_profile` if they wish to respond to `--profile`.
  (Jon Rowe)
* Extract remaining formatter state to reporter and notifications. Introduce
  `ExamplesNotification` to share information about examples that was previously
  held in `BaseFormatter`. (Jon Rowe)

Enhancements:

* Add `config.default_formatter` attribute, which can be used to set a
  formatter which will only be used if no other formatter is set
  (e.g. via `--formatter`). (Myron Marston)
* Support legacy colour definitions in `LegacyFormatterAdaptor`. (Jon Rowe)
* Migrate `execution_result` (exposed by metadata) from a hash to a
  first-class object with appropriate attributes. `status` is now
  stored and returned as a symbol rather than a string. It retains
  deprecated hash behavior for backwards compatibility. (Myron Marston)
* Provide console code helper for formatters. (Jon Rowe)
* Use raw ruby hashes for the metadata hashes rather than a subclass of
  a hash. Computed metadata entries are now computed in advance rather
  than being done lazily on first access. (Myron Marston)
* Add `:block` metadata entry to the example metadata, bringing
  parity with `:block` in the example group metadata. (Myron Marston)
* Add `fspecify` and `fexample` as aliases of `specify` and `example`
  with `:focus => true` metadata for parity with `fit`. (Myron Marston)
* Add legacy support for `colorize_summary`. (Jon Rowe)
* Restructure runner so it can be more easily customized in a subclass
  for an alternate runner. (Ben Hoskings)
* Document `RSpec::Core::ConfigurationOptions` as an officially
  supported public API. (Myron Marston)
* Add `--deprecation-out` CLI option which directs deprecation warnings
  to the named file. (Myron Marston)
* Minitest 5 compatability for `expect_with :stdlib` (now available as
  `expect_with :minitest`). (Xavier Shay)
* Reporter now notifies formatters of the load time of RSpec and your
  specs via `StartNotification` and `SummaryNotification`. (Jon Rowe)
* Add `disable_monkey_patching!` config option that disables all monkey
  patching from whatever pieces of RSpec you use. (Alexey Fedorov)
* Add `Pathname` support for setting all output streams. (Aaron Kromer)
* Add `config.define_derived_metadata`, which can be used to apply
  additional metadata to all groups or examples that match a given
  filter. (Myron Marston)
* Provide formatted and colorized backtraces via `FailedExampleNotification`
  and send `PendingExampleFixedNotifications` when the error is due to a
  passing spec you expect to fail. (Jon Rowe)
* Add `dump_profile` to formatter API to allow formatters to implement
  support for `--profile`. (Jon Rowe)
* Allow colourising text via `ConsoleCodes` with RSpec 'states'
  (e.g. `:success`, `:failure`) rather than direct colour codes. (Jon Rowe)
* Expose `fully_formatted` methods off the formatter notification objects
  that make it easy for a custom formatter to produce formatted output
  like rspec-core's. (Myron Marston)

Bug Fixes:

* Fix `spec_helper.rb` file generated by `rspec --init` so that the
  recommended settings correctly use the documentation formatter
  when running one file. (Myron Marston)
* Fix ordering problem where descriptions were generated after
  tearing down mocks, which resulted in unexpected exceptions.
  (Bradley Schaefer, Aaron Kromer, Andrey Savchenko)
* Allow a symbol to be used as an implicit subject (e.g. `describe
  :foo`). (Myron Marston)
* Prevent creating an isolated context (i.e. using `RSpec.describe`) when
  already inside a context. There is no reason to do this, and it could
  potentially cause unexpected bugs. (Xavier Shay)
* Fix shared example group scoping so that when two shared example
  groups share the same name at different levels of nested contexts,
  the one in the nearest context is used. (Myron Marston)
* Fix `--warnings` option so that it enables warnings immediately so
  that it applies to files loaded by `--require`. (Myron Marston)
* Issue a warning when you set `config.deprecation_stream` too late for
  it to take effect because the reporter has already been setup. (Myron Marston)
* Add the full `RSpec::Core::Example` interface to the argument yielded
  to `around` hooks. (Myron Marston)
* Line number always takes precendence when running specs with filters.
  (Xavier Shay)
* Ensure :if and :unless metadata filters are treated as a special case
  and are always in-effect. (Bradley Schaefer)
* Ensure the currently running installation of RSpec is used when
  the rake task shells out to `rspec`, even if a newer version is also
  installed. (Postmodern)
* Using a legacy formatter as default no longer causes an infinite loop.
  (Xavier Shay)

### 3.0.0.beta2 / 2014-02-17
[Full Changelog](http://github.com/rspec/rspec-core/compare/v3.0.0.beta1...v3.0.0.beta2)

Breaking Changes for 3.0.0:

* Make `mock_with` option more strict. Strings are no longer supported
  (e.g. `mock_with "mocha"`) -- use a symbol instead. Also, unrecognized
  values will now result in an error rather than falling back to the
  null mocking adapter. If you want to use the null mocking adapter,
  use `mock_with :nothing` (as has been documented for a long time).
  (Myron Marston)
* Remove support for overriding RSpec's built-in `:if` and `:unless`
  filters. (Ashish Dixit)
* Custom formatters are now required to call
  `RSpec::Core::Formatters.register(formatter_class, *notifications)`
  where `notifications` is the list of events the formatter wishes to
  be notified about. Notifications are handled by methods matching the
  names on formatters. This allows us to add or remove notifications
  without breaking existing formatters. (Jon Rowe)
* Change arguments passed to formatters. Rather than passing multiple
  arguments (which limits are ability to add additional arguments as
  doing so would break existing formatters), we now pass a notification
  value object that exposes the same data via attributes. This will
  allow us to add new bits of data to a notification event without
  breaking existing formatters. (Jon Rowe)
* Remove support for deprecated `:alias` option for
  `RSpec.configuration.add_setting`. (Myron Marston)
* Remove support for deprecated `RSpec.configuration.requires = [...]`.
  (Myron Marston)
* Remove support for deprecated `--formatter` CLI option. (Myron Marston)
* Remove support for deprecated `--configure` CLI option. (Myron Marston)
* Remove support for deprecated `RSpec::Core::RakeTask#spec_opts=`.
  (Myron Marston)
* An example group level `pending` block or `:pending` metadata now executes
  the example and cause a failure if it passes, otherwise it will be pending if
  it fails. The old "never run" behaviour is still used for `xexample`, `xit`,
  and `xspecify`, or via a new `skip` method or `:skip` metadata option.
  (Xavier Shay)
* After calling `pending` inside an example, the remainder of the example will
  now be run. If it passes a failure is raised, otherwise the example is marked
  pending. The old "never run" behaviour is provided a by a new `skip` method.
  (Xavier Shay)
* Pending blocks inside an example have been removed as a feature with no
  direct replacement. Use `skip` or `pending` without a block. (Xavier Shay)
* Pending statement is no longer allowed in `before(:all)` hooks. Use `skip`
  instead.  (Xavier Shay)
* Remove `show_failures_in_pending_blocks` configuration option. (Xavier Shay)
* Remove support for specifying the documentation formatter using
  's', 'n', 'spec' or 'nested'. (Jon Rowe)

Enhancements:

* Add example run time to JSON formatter output. (Karthik Kastury)
* Add more suggested settings to the files generated by
  `rspec --init`. (Myron Marston)
* Add `config.alias_example_group_to`, which can be used to define a
  new method that defines an example group with the provided metadata.
  (Michi Huber)
* Add `xdescribe` and `xcontext` as shortcuts to skip an example group.
  (Myron Marston)
* Add `fdescribe` and `fcontext` as shortcuts to focus an example group.
  (Myron Marston)
* Don't autorun specs via `#at_exit` by default. `require 'rspec/autorun'`
  is only needed when running specs via `ruby`, as it always has been.
  Running specs via `rake` or `rspec` are both unaffected. (Ben Hoskings)
* Add `expose_dsl_globally` config option, defaulting to true. When disabled
  it will remove the monkey patches rspec-core adds to `main` and `Module`
  (e.g. `describe`, `shared_examples_for`, etc).  (Jon Rowe)
* Expose RSpec DSL entry point methods (`describe`,
  `shared_examples_for`, etc) on the `RSpec` constant. Intended for use
  when `expose_dsl_globally` is set to `false`. (Jon Rowe)
* For consistency, expose all example group aliases (including
  `context`) on the `RSpec` constant. If `expose_dsl_globally` is set to
  `true`, also expose them on `main` and `Module`. Historically, only `describe`
  was exposed. (Jon Rowe, Michi Huber)
* Add hook scope `:example` as an alias for `:each`, and `:context` as an alias
  for `:all`. (John Feminella)

Bug Fixes:

* Fix failure (undefined method `path`) in end-of-run summary
  when `raise_errors_for_deprecations!` is configured. (Myron Marston)
* Issue error when attempting to use `-i` or `--I` on command line,
  too close to `-I` to be considered short hand for `--init`. (Jon Rowe)
* Prevent adding formatters to an output target if the same
  formatter has already been added to that output. (Alex Peattie)
* Allow a matcher-generated example description to be used when
  the example is pending. (Myron Marston)
* Ensure the configured `failure_exit_code` is used by the rake
  task when there is a failure. (Jon Rowe)
* Restore behaviour whereby system exclusion filters take priority over working
  directory (was broken in beta1). (Jon Rowe)
* Prevent RSpec mangling file names that have substrings containing `line_number`
  or `default_path`. (Matijs van Zuijlen)
* Fix failure line detection so that it handles relative file paths
  (which can happen when running specs through `ruby` using `rspec/autorun`).
  (Myron Marston, #1829)

### 3.0.0.beta1 / 2013-11-07
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.99.1...v3.0.0.beta1)

Breaking Changes for 3.0.0:

* Remove explicit support for 1.8.6. (Jon Rowe)
* Remove `RSpec::Core::ExampleGroup#example` and
  `RSpec::Core::ExampleGroup#running_example` methods. If you need
  access to the example (e.g. to get its metadata), use a block arg
  instead. (David Chelimsky)
* Remove `TextMateFormatter`, it has been moved to `rspec-tmbundle`.
  (Aaron Kromer)
* Remove RCov integration. (Jon Rowe)
* Remove deprecated support for RSpec 1 constructs (Myron Marston):
  * The `Spec` and `Rspec` constants (rather than `RSpec`).
  * `Spec::Runner.configure` rather than `RSpec.configure`.
  * `Rake::SpecTask` rather than `RSpec::Core::RakeTask`.
* Remove deprecated support for `share_as`. (Myron Marston)
* Remove `--debug` option (and corresponding option on
  `RSpec::Core::Configuration`). Instead, use `-r<debugger gem name>` to
  load whichever debugger gem you wish to use (e.g. `ruby-debug`,
  `debugger`, or `pry`). (Myron Marston)
* Extract Autotest support to a seperate gem. (Jon Rowe)
* Raise an error when a `let` or `subject` declaration is
  accessed in a `before(:all)` or `after(:all)` hook. (Myron Marston)
* Extract `its` support to a separate gem. (Peter Alfvin)
* Disallow use of a shared example group from sibling contexts, making them
  fully isolated. 2.14 and 2.99 allowed this but printed a deprecation warning.
  (Jon Rowe)
* Remove `RSpec::Core::Configuration#output` and
  `RSpec::Core::Configuration#out` aliases of
  `RSpec::Core::Configuration#output_stream`. (Myron Marston)
* Remove legacy ordering APIs deprecated in 2.99.0.beta1. (Myron
  Marston)

Enhancements:

* Replace unmaintained syntax gem with coderay gem. (Xavier Shay)
* Times in profile output are now bold instead of `failure_color`.
  (Matthew Boedicker)
* Add `--no-fail-fast` command line option. (Gonzalo Rodríguez-Baltanás Díaz)
* Runner now considers the local system ip address when running under Drb.
  (Adrian CB)
* JsonFormatter now includes `--profile` information. (Alex / @MasterLambaster)
* Always treat symbols passed as metadata args as hash
  keys with true values. RSpec 2 supported this with the
  `treat_symbols_as_metadata_keys_with_true_values` but
  now this behavior is always enabled. (Myron Marston)
* Add `--dry-run` option, which prints the formatter output
  of your suite without running any examples or hooks.
  (Thomas Stratmann, Myron Marston)
* Document the configuration options and default values in the `spec_helper.rb`
  file that is generated by RSpec. (Parker Selbert)
* Give generated example group classes a friendly name derived
  from the docstring, rather than something like "Nested_2".
  (Myron Marston)
* Avoid affecting randomization of user code when shuffling
  examples so that users can count on their own seeds
  working. (Travis Herrick)
* Ordering is no longer a single global property of the test suite.
  Each group can pick an ordering using `:order` metadata. (Andy
  Lindeman, Sam Phippen, Myron Marston)
* Allow named custom ordering strategies to be registered, which can
  then be used on individual example groups. (Andy Lindeman, Sam
  Phippen, Myron Marston)

Deprecations:

* `treat_symbols_as_metadata_keys_with_true_values` is deprecated and no
  longer has an affect now that the behavior it enabled is always
  enabled. (Myron Marston)

### 2.99.2 / 2014-08-19
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.99.1...v2.99.2)

Enhancements:

* Improve deprecation warning for RSpec 3 change in `describe <a symbol>`
  behavior. (Jon Rowe, #1667)

### 2.99.1 / 2014-06-19
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.99.0...v2.99.1)

Bug Fixes:

* Add missing deprecation warning for when `RSpec::Core::Runner` is used
  multiple times in the same process. In 2.x RSpec's global state was
  automatically cleared between runs but in 3.0 you need to call `RSpec.reset`
  manually in these situations. (Sam Phippen, #1587)
* Prevent deprecation being accidentally issues when doubles used with `be_`
  matchers due to automatically generated descriptions. (Jon Rowe, #1573)
* Load `rspec/core` when loading `rspec/core/rake_task` to ensure we can
  issue deprecations correctly. (Jon Rowe, #1612)

### 2.99.0 / 2014-06-01
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.99.0.rc1...v2.99.0)

Bug Fixes:

* Fix `BaseTextFormatter` so that it does not re-close a closed output
  stream. (Myron Marston)
* Use `RSpec::Configuration#backtrace_exclusion_patterns` rather than the
  deprecated `RSpec::Configuration#backtrace_clean_patterns` when mocking
  with rr. (David Dollar)

### 2.99.0.rc1 / 2014-05-18
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.99.0.beta2...v2.99.0.rc1)

Enhancements:

* Add `--deprecation-out` CLI option which directs deprecation warnings
  to the named file. (Myron Marston)
* Backport support for `skip` in metadata to skip execution of an example.
  (Xavier Shay, #1472)
* Add `Pathname` support for setting all output streams. (Aaron Kromer)
* Add `test_unit` and `minitest` expectation frameworks. (Aaron Kromer)

Deprecations:

* Deprecate `RSpec::Core::Pending::PendingDeclaredInExample`, use
  `SkipDeclaredInExample` instead. (Xavier Shay)
* Issue a deprecation when `described_class` is accessed from within
  a nested `describe <SomeClass>` example group, since `described_class`
  will return the innermost described class in RSpec 3 rather than the
  outermost described class, as it behaved in RSpec 2. (Myron Marston)
* Deprecate `RSpec::Core::FilterManager::DEFAULT_EXCLUSIONS`,
  `RSpec::Core::FilterManager::STANDALONE_FILTERS` and use of
  `#empty_without_conditional_filters?` on those filters. (Sergey Pchelincev)
* Deprecate `RSpec::Core::Example#options` in favor of
  `RSpec::Core::Example#metadata`. (Myron Marston)
* Issue warning when passing a symbol or hash to `describe` or `context`
  as the first argument. In RSpec 2.x this would be treated as metadata
  but in RSpec 3 it'll be treated as the described object. To continue
  having it treated as metadata, pass a description before the symbol or
  hash. (Myron Marston)
* Deprecate `RSpec::Core::BaseTextFormatter::VT100_COLORS` and
  `RSpec::Core::BaseTextFormatter::VT100_COLOR_CODES` in favour
  of `RSpec::Core::BaseTextFormatter::ConsoleCodes::VT100_CODES` and
  `RSpec::Core::BaseTextFormatter::ConsoleCodes::VT100_CODE_VALUES`.
  (Jon Rowe)
* Deprecate `RSpec::Core::ExampleGroup.display_name` in favor of
  `RSpec::Core::ExampleGroup.description`. (Myron Marston)
* Deprecate `RSpec::Core::ExampleGroup.describes` in favor of
  `RSpec::Core::ExampleGroup.described_class`. (Myron Marston)
* Deprecate `RSpec::Core::ExampleGroup.alias_example_to` in favor of
  `RSpec::Core::Configuration#alias_example_to`. (Myron Marston)
* Deprecate `RSpec::Core::ExampleGroup.alias_it_behaves_like_to` in favor
  of `RSpec::Core::Configuration#alias_it_behaves_like_to`. (Myron Marston)
* Deprecate `RSpec::Core::ExampleGroup.focused` in favor of
  `RSpec::Core::ExampleGroup.focus`. (Myron Marston)
* Add deprecation warning for `config.filter_run :focused` since
  example aliases `fit` and `focus` will no longer include
  `:focused` metadata but will continue to include `:focus`. (Myron Marston)
* Deprecate filtering by `:line_number` (e.g. `--line-number` from the
  CLI). Use location filtering instead. (Myron Marston)
* Deprecate `--default_path` as an alternative to `--default-path`. (Jon Rowe)
* Deprecate `RSpec::Core::Configuration#warnings` in favor of
  `RSpec::Core::Configuration#warnings?`. (Myron Marston)
* Deprecate `share_examples_for` in favor of `shared_examples_for` or
  just `shared_examples`. (Myron Marston)
* Deprecate `RSpec::Core::CommandLine` in favor of
  `RSpec::Core::Runner`. (Myron Marston)
* Deprecate `#color_enabled`, `#color_enabled=` and `#color?` in favour of
  `#color`, `#color=` and `#color_enabled? output`. (Jon Rowe)
* Deprecate `#filename_pattern` in favour of `#pattern`. (Jon Rowe)
* Deprecate `#backtrace_cleaner` in favour of `#backtrace_formatter`. (Jon Rowe)
* Deprecate mutating `RSpec::Configuration#formatters`. (Jon Rowe)
* Deprecate `stdlib` as an available expectation framework in favour of
  `test_unit` and `minitest`. (Aaron Kromer)

Bug Fixes:

* Issue a warning when you set `config.deprecation_stream` too late for
  it to take effect because the reporter has already been setup. (Myron Marston)
* `skip` with a block should not execute the block. (Xavier Shay)

### 2.99.0.beta2 / 2014-02-17
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.99.0.beta1...v2.99.0.beta2)

Enhancements:

* Add `is_expected` for one-liners that read well with the
  `expect`-based syntax. `is_expected` is simply defined as
  `expect(subject)` and can be used in an expression like:
  `it { is_expected.to read_well }`. (Myron Marston)
* Backport `skip` from RSpec 3, which acts like `pending` did in RSpec 2
  when not given a block, since the behavior of `pending` is changing in
  RSpec 3. (Xavier Shay)

Deprecations:

* Deprecate inexact `mock_with` config options. RSpec 3 will only support
  the exact symbols `:rspec`, `:mocha`, `:flexmock`, `:rr` or `:nothing`
  (or any module that implements the adapter interface). RSpec 2 did
  fuzzy matching but this will not be supported going forward.
  (Myron Marston)
* Deprecate `show_failures_in_pending_blocks` config option. To achieve
  the same behavior as the option enabled, you can use a custom
  formatter instead. (Xavier Shay)
* Add a deprecation warning for the fact that the behavior of `pending`
  is changing in RSpec 3 -- rather than skipping the example (as it did
  in 2.x when no block was provided), it will run the example and mark
  it as failed if no exception is raised. Use `skip` instead to preserve
  the old behavior. (Xavier Shay)
* Deprecate 's', 'n', 'spec' and 'nested' as aliases for documentation
  formatter. (Jon Rowe)
* Deprecate `RSpec::Core::Reporter#abort` in favor of
  `RSpec::Core::Reporter#finish`. (Jon Rowe)

Bug Fixes:

* Fix failure (undefined method `path`) in end-of-run summary
  when `raise_errors_for_deprecations!` is configured. (Myron Marston)
* Fix issue were overridding spec ordering from the command line wasn't
  fully recognised interally. (Jon Rowe)

### 2.99.0.beta1 / 2013-11-07
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.7...v2.99.0.beta1)

Enhancements

* Block-based DSL methods that run in the context of an example
  (`it`, `before(:each)`, `after(:each)`, `let` and `subject`)
  now yield the example as a block argument. (David Chelimsky)
* Warn when the name of more than one example group is submitted to
  `include_examples` and it's aliases. (David Chelimsky)
* Add `expose_current_running_example_as` config option for
  use during the upgrade process when external gems use the
  deprecated `RSpec::Core::ExampleGroup#example` and
  `RSpec::Core::ExampleGroup#running_example` methods. (Myron Marston)
* Limit spamminess of deprecation messages. (Bradley Schaefer, Loren Segal)
* Add `config.raise_errors_for_deprecations!` option, which turns
  deprecations warnings into errors to surface the full backtrace
  of the call site. (Myron Marston)

Deprecations

* Deprecate `RSpec::Core::ExampleGroup#example` and
  `RSpec::Core::ExampleGroup#running_example` methods. If you need
  access to the example (e.g. to get its metadata), use a block argument
  instead. (David Chelimsky)
* Deprecate use of `autotest/rspec2` in favour of `rspec-autotest`. (Jon Rowe)
* Deprecate RSpec's built-in debugger support. Use a CLI option like
  `-rruby-debug` (for the ruby-debug gem) or `-rdebugger` (for the
  debugger gem) instead. (Myron Marston)
* Deprecate `RSpec.configuration.treat_symbols_as_metadata_keys_with_true_values = false`.
  RSpec 3 will not support having this option set to `false`. (Myron Marston)
* Deprecate accessing a `let` or `subject` declaration in
  a `after(:all)` hook. (Myron Marston, Jon Rowe)
* Deprecate built-in `its` usage in favor of `rspec-its` gem due to planned
  removal in RSpec 3. (Peter Alfvin)
* Deprecate `RSpec::Core::PendingExampleFixedError` in favor of
  `RSpec::Core::Pending::PendingExampleFixedError`. (Myron Marston)
* Deprecate `RSpec::Core::Configuration#out` and
  `RSpec::Core::Configuration#output` in favor of
  `RSpec::Core::Configuration#output_stream`. (Myron Marston)
* Deprecate legacy ordering APIs.
  * You should use `register_ordering(:global)` instead of these:
    * `RSpec::Core::Configuration#order_examples`
    * `RSpec::Core::Configuration#order_groups`
    * `RSpec::Core::Configuration#order_groups_and_examples`
  * These are deprecated with no replacement because in RSpec 3
    ordering is a property of individual example groups rather than
    just a global property of the entire test suite:
    * `RSpec::Core::Configuration#order`
    * `RSpec::Core::Configuration#randomize?`
  * `--order default` is deprecated in favor of `--order defined`
  (Myron Marston)

### 2.14.8 / 2014-02-27
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.7...v2.14.8)

Bug fixes:

* Fix regression with the `textmateformatter` that prevented backtrace links
  from being clickable. (Stefan Daschek)

### 2.14.7 / 2013-10-29
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.6...v2.14.7)

Bug fixes:

* Fix regression in 2.14.6 that broke the Fivemat formatter.
  It depended upon either
  `example.execution_result[:exception].pending_fixed?` (which
  was removed in 2.14.6 to fix an issue with frozen error objects)
  or `RSpec::Core::PendingExampleFixedError` (which was renamed
  to `RSpec::Core::Pending::PendingExampleFixedError` in 2.8.
  This fix makes a constant alias for the old error name.
  (Myron Marston)

### 2.14.6 / 2013-10-15
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.5...v2.14.6)

Bug fixes:

* Format stringified numbers correctly when mathn library is loaded.
  (Jay Hayes)
* Fix an issue that prevented the use of frozen error objects. (Lars
  Gierth)

### 2.14.5 / 2013-08-13
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.4...v2.14.5)

Bug fixes:

* Fix a `NoMethodError` that was being raised when there were no shared
  examples or contexts declared and `RSpec.world.reset` is invoked.
  (thepoho, Jon Rowe, Myron Marston)
* Fix a deprecation warning that was being incorrectly displayed when
  `shared_examples` are declared at top level in a `module` scope.
  (Jon Rowe)
* Fix after(:all) hooks so consecutive (same context) scopes will run even if
  one raises an error. (Jon Rowe, Trejkaz)
* JsonFormatter no longer dies if `dump_profile` isn't defined (Alex / @MasterLambaster, Jon Rowe)

### 2.14.4 / 2013-07-21
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.3...v2.14.4)

Bug fixes

* Fix regression in 2.14: ensure configured requires (via `-r` option)
  are loaded before spec files are loaded. This allows the spec files
  to programatically change the file pattern (Jon Rowe).
* Autoload `RSpec::Mocks` and `RSpec::Expectations` when referenced if
  they are not already loaded (`RSpec::Matches` has been autoloaded
  for a while). In the `rspec` gem, we changed it recently to stop
  loading `rspec/mocks` and `rspec/expectations` by default, as some
  users reported problems where they were intending to use mocha,
  not rspec-mocks, but rspec-mocks was loaded and causing a conflict.
  rspec-core loads mocks and expectations at the appropriate time, so
  it seemed like a safe change -- but caused a problem for some authors
  of libraries that integrate with RSpec. This fixes that problem.
  (Myron Marston)
* Gracefully handle a command like `rspec --profile path/to/spec.rb`:
  the `path/to/spec.rb` arg was being wrongly treated as the `profile`
  integer arg, which got cast `0` using `to_i`, causing no profiled
  examples to be printed. (Jon Rowe)

### 2.14.3 / 2013-07-13
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.2...v2.14.3)

Bug fixes

* Fix deprecation notices issued from `RSpec::Core::RakeTask` so
  that they work properly when all of rspec-core is not loaded.
  (This was a regression in 2.14) (Jon Rowe)

### 2.14.2 / 2013-07-09
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.1...v2.14.2)

Bug fixes

* Fix regression caused by 2.14.1 release: formatters that
  report that they `respond_to?` a notification, but had
  no corresponding method would raise an error when registered.
  The new fix is to just implement `start` on the deprecation
  formatter to fix the original JRuby/ruby-debug issue.
  (Jon Rowe)

### 2.14.1 / 2013-07-08
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.0...v2.14.1)

Bug fixes

* Address deprecation formatter failure when using `ruby-debug` on
  JRuby: fix `RSpec::Core::Reporter` to not send a notification
  when the formatter's implementation of the notification method
  comes from `Kernel` (Alex Portnov, Jon Rowe).

### 2.14.0 / 2013-07-06
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.14.0.rc1...v2.14.0)

Enhancements

* Apply focus to examples defined with `fit` (equivalent of
  `it "description", focus: true`) (Michael de Silva)

Bug fix

* Ensure methods defined by `let` take precedence over others
  when there is a name collision (e.g. from an included module).
  (Jon Rowe, Andy Lindeman and Myron Marston)

### 2.14.0.rc1 / 2013-05-27
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.13.1...v2.14.0.rc1)

Enhancements

* Improved Windows detection inside Git Bash, for better `--color` handling.
* Add profiling of the slowest example groups to `--profile` option.
  The output is sorted by the slowest average example groups.
* Don't show slow examples if there's a failure and both `--fail-fast`
  and `--profile` options are used (Paweł Gościcki).
* Rather than always adding `spec` to the load path, add the configured
  `--default-path` to the load path (which defaults to `spec`). This
  better supports folks who choose to put their specs in a different
  directory (John Feminella).
* Add some logic to test time duration precision. Make it a
  function of time, dropping precision as the time increases. (Aaron Kromer)
* Add new `backtrace_inclusion_patterns` config option. Backtrace lines
  that match one of these patterns will _always_ be included in the
  backtrace, even if they match an exclusion pattern, too (Sam Phippen).
* Support ERB trim mode using the `-` when parsing `.rspec` as ERB
  (Gabor Garami).
* Give a better error message when let and subject are called without a block.
  (Sam Phippen).
* List the precedence of `.rspec-local` in the configuration documentation
  (Sam Phippen)
* Support `{a,b}` shell expansion syntax in `--pattern` option
  (Konstantin Haase).
* Add cucumber documentation for --require command line option
  (Bradley Schaefer)
* Expose configuration options via config:
  * `config.libs` returns the libs configured to be added onto the load path
  * `full_backtrace?` returns the state of the backtrace cleaner
  * `debug?` returns true when the debugger is loaded
  * `line_numbers` returns the line numbers we are filtering by (if any)
  * `full_description` returns the RegExp used to filter descriptions
  (Jon Rowe)
* Add setters for RSpec.world and RSpec.configuration (Alex Soulim)
* Configure ruby's warning behaviour with `--warnings` (Jon Rowe)
* Fix an obscure issue on old versions of `1.8.7` where `Time.dup` wouldn't
  allow access to `Time.now` (Jon Rowe)
* Make `shared_examples_for` context aware, so that keys may be safely reused
  in multiple contexts without colliding. (Jon Rowe)
* Add a configurable `deprecation_stream` (Jon Rowe)
* Publish deprecations through a formatter (David Chelimsky)

Bug fixes

* Make JSON formatter behave the same when it comes to `--profile` as
  the text formatter (Paweł Gościcki).
* Fix named subjects so that if an inner group defines a method that
  overrides the named method, `subject` still retains the originally
  declared value (Myron Marston).
* Fix random ordering so that it does not cause `rand` in examples in
  nested sibling contexts to return the same value (Max Shytikov).
* Use the new `backtrace_inclusion_patterns` config option to ensure
  that folks who develop code in a directory matching one of the default
  exclusion patterns (e.g. `gems`) still get the normal backtrace
  filtering (Sam Phippen).
* Fix ordering of `before` hooks so that `before` hooks declared in
  `RSpec.configure` run before `before` hooks declared in a shared
  context (Michi Huber and Tejas Dinkar).
* Fix `Example#full_description` so that it gets filled in by the last
  matcher description (as `Example#description` already did) when no
  doc string has been provided (David Chelimsky).
* Fix the memoized methods (`let` and `subject`) leaking `define_method`
  as a `public` method. (Thomas Holmes and Jon Rowe) (#873)
* Fix warnings coming from the test suite. (Pete Higgins)

Deprecations

* Deprecate `Configuration#backtrace_clean_patterns` in favor of
  `Configuration#backtrace_exclusion_patterns` for greater consistency
  and symmetry with new `backtrace_inclusion_patterns` config option
  (Sam Phippen).
* Deprecate `Configuration#requires=` in favor of using ruby's
  `require`. Requires specified by the command line can still be
  accessed by the `Configuration#require` reader. (Bradley Schaefer)
* Deprecate calling `SharedExampleGroups` defined across sibling contexts
  (Jon Rowe)

### 2.13.1 / 2013-03-12
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.13.0...v2.13.1)

Bug fixes

* Use hook classes as proxies rather than extending hook blocks to support
  lambdas for before/after/around hooks. (David Chelimsky)
* Fix regression in 2.13.0 that caused confusing behavior when overriding
  a named subject with an unnamed subject in an inner group and then
  referencing the outer group subject's name. The fix for this required
  us to disallow using `super` in a named subject (which is confusing,
  anyway -- named subjects create 2 methods, so which method on the
  parent example group are you `super`ing to?) but `super` in an unnamed
  subject continues to work (Myron Marston).
* Do not allow a referenced `let` or `subject` in `before(:all)` to cause
  other `let` declarations to leak across examples (Myron Marston).
* Work around odd ruby 1.9 bug with `String#match` that was triggered
  by passing it a regex from a `let` declaration. For more info, see
  http://bugs.ruby-lang.org/issues/8059 (Aaron Kromer).
* Add missing `require 'set'` to `base_text_formatter.rb` (Tom
  Anderson).

Deprecations

* Deprecate accessing `let` or `subject` declarations in `before(:all)`.
  These were not intended to be called in a `before(:all)` hook, as
  they exist to define state that is reset between each example, while
  `before(:all)` exists to define state that is shared across examples
  in an example group (Myron Marston).

### 2.13.0 / 2013-02-23
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.12.2...v2.13.0)

Enhancements

* Allow `--profile` option to take a count argument that
  determines the number of slow examples to dump
  (Greggory Rothmeier).
* Add `subject!` that is the analog to `let!`. It defines an
  explicit subject and sets a `before` hook that will invoke
  the subject (Zubin Henner).
* Fix `let` and `subject` declaration so that `super`
  and `return` can be used in them, just like in a normal
  method. (Myron Marston)
* Allow output colors to be configured individually.
  (Charlie Maffitt)
* Always dump slow examples when `--profile` option is given,
  even when an example failed (Myron Marston).

Bug fixes

* Don't blow up when dumping error output for instances
  of anonymous error classes (Myron Marston).
* Fix default backtrace filters so lines from projects
  containing "gems" in the name are not filtered, but
  lines from installed gems still are (Myron Marston).
* Fix autotest command so that is uses double quotes
  rather than single quotes for windows compatibility
  (Jonas Tingeborn).
* Fix `its` so that uses of `subject` in a `before` or `let`
  declaration in the parent group continue to reference the
  parent group's subject. (Olek Janiszewski)

### 2.12.2 / 2012-12-13
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.12.1...v2.12.2)

Bug fixes

* Fix `RSpec::Core::RakeTask` so that it is compatible with rake 0.8.7
  on ruby 1.8.7. We had accidentally broke it in the 2.12 release
  (Myron Marston).
* Fix `RSpec::Core::RakeTask` so it is tolerant of the `Rspec` constant
  for backwards compatibility (Patrick Van Stee)

### 2.12.1 / 2012-12-01
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.12.0...v2.12.1)

Bug fixes

* Specs are run even if another at\_exit hook calls `exit`. This allows
  Test::Unit and RSpec to run together. (Suraj N. Kurapati)
* Fix full doc string concatenation so that it handles the case of a
  method string (e.g. "#foo") being nested under a context string
  (e.g. "when it is tuesday"), so that we get "when it is tuesday #foo"
  rather than "when it is tuesday#foo". (Myron Marston)
* Restore public API I unintentionally broke in 2.12.0:
  `RSpec::Core::Formatters::BaseFormatter#format_backtrce(backtrace, example)`
  (Myron Marston).

### 2.12.0 / 2012-11-12
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.11.1...v2.12.0)

Enhancements

* Add support for custom ordering strategies for groups and examples.
  (Myron Marston)
* JSON Formatter (Alex Chaffee)
* Refactor rake task internals (Sam Phippen)
* Refactor HtmlFormatter (Pete Hodgson)
* Autotest supports a path to Ruby that contains spaces (dsisnero)
* Provide a helpful warning when a shared example group is redefined.
  (Mark Burns).
* `--default_path` can be specified as `--default-line`. `--line_number` can be
  specified as `--line-number`. Hyphens are more idiomatic command line argument
  separators (Sam Phippen).
* A more useful error message is shown when an invalid command line option is
  used (Jordi Polo).
* Add `format_docstrings { |str| }` config option. It can be used to
  apply formatting rules to example group and example docstrings.
  (Alex Tan)
* Add support for an `.rspec-local` options file. This is intended to
  allow individual developers to set options in a git-ignored file that
  override the common project options in `.rspec`. (Sam Phippen)
* Support for mocha 0.13.0. (Andy Lindeman)

Bug fixes

* Remove override of `ExampleGroup#ancestors`. This is a core ruby method that
  RSpec shouldn't override. Instead, define `ExampleGroup#parent_groups`. (Myron
  Marston)
* Limit monkey patching of shared example/context declaration methods
  (`shared_examples_for`, etc.) to just the objects that need it rather than
  every object in the system (Myron Marston).
* Fix Metadata#fetch to support computed values (Sam Goldman).
* Named subject can now be referred to from within subject block in a nested
  group (tomykaira).
* Fix `fail_fast` so that it properly exits when an error occurs in a
  `before(:all) hook` (Bradley Schaefer).
* Make the order spec files are loaded consistent, regardless of the
  order of the files returned by the OS or the order passed at
  the command line (Jo Liss and Sam Phippen).
* Ensure instance variables from `before(:all)` are always exposed
  from `after(:all)`, even if an error occurs in `before(:all)`
  (Sam Phippen).
* `rspec --init` no longer generates an incorrect warning about `--configure`
  being deprecated (Sam Phippen).
* Fix pluralization of `1 seconds` (Odin Dutton)
* Fix ANSICON url (Jarmo Pertman)
* Use dup of Time so reporting isn't clobbered by examples that modify Time
  without properly restoring it. (David Chelimsky)

Deprecations

* `share_as` is no longer needed. `shared_context` and/or
  `RSpec::SharedContext` provide better mechanisms (Sam Phippen).
* Deprecate `RSpec.configuration` with a block (use `RSpec.configure`).


### 2.11.1 / 2012-07-18
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.11.0...v2.11.1)

Bug fixes

* Fix the way we autoload RSpec::Matchers so that custom matchers can be
  defined before rspec-core has been configured to definitely use
  rspec-expectations. (Myron Marston)
* Fix typo in --help message printed for -e option. (Jo Liss)
* Fix ruby warnings. (Myron Marston)
* Ignore mock expectation failures when the example has already failed.
  Mock expectation failures have always been ignored in this situation,
  but due to my changes in 27059bf1 it was printing a confusing message.
  (Myron Marston).

### 2.11.0 / 2012-07-07
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.10.1...v2.11.0)

Enhancements

* Support multiple `--example` options. (Daniel Doubrovkine @dblock)
* Named subject e.g. `subject(:article) { Article.new }`
    * see [http://blog.davidchelimsky.net/2012/05/13/spec-smell-explicit-use-of-subject/](http://blog.davidchelimsky.net/2012/05/13/spec-smell-explicit-use-of-subject/)
      for background.
    * thanks to Bradley Schaefer for suggesting it and Avdi Grimm for almost
      suggesting it.
* `config.mock_with` and `config.expect_with` yield custom config object to a
  block if given
    * aids decoupling from rspec-core's configuation
* `include_context` and `include_examples` support a block, which gets eval'd
  in the current context (vs the nested context generated by `it_behaves_like`).
* Add `config.order = 'random'` to the `spec_helper.rb` generated by `rspec
  --init`.
* Delay the loading of DRb (Myron Marston).
* Limit monkey patching of `describe` onto just the objects that need it rather
  than every object in the system (Myron Marston).

Bug fixes

* Support alternative path separators. For example, on Windows, you can now do
  this: `rspec spec\subdir`. (Jarmo Pertman @jarmo)
* When an example raises an error and an after or around hook does as
  well, print out the hook error. Previously, the error was silenced and
  the user got no feedback about what happened. (Myron Marston)
* `--require` and `-I` are merged among different configuration sources (Andy
  Lindeman)
* Delegate to mocha methods instead of aliasing them in mocha adapter.

### 2.10.1 / 2012-05-19
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.10.0...v2.10.1)

Bug fixes

* `RSpec.reset` properly reinits configuration and world
* Call `to_s` before `split` on exception messages that might not always be
  Strings (slyphon)

### 2.10.0 / 2012-05-03
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.9.0...v2.10.0)

Enhancements

* Add `prepend_before` and `append_after` hooks (preethiramdev)
    * intended for extension libs
    * restores rspec-1 behavior
* Reporting of profiled examples (moro)
    * Report the total amount of time taken for the top slowest examples.
    * Report what percentage the slowest examples took from the total runtime.

Bug fixes

* Properly parse `SPEC_OPTS` options.
* `example.description` returns the location of the example if there is no
  explicit description or matcher-generated description.
* RDoc fixes (Grzegorz Świrski)
* Do not modify example ancestry when dumping errors (Michael Grosser)

### 2.9.0 / 2012-03-17
[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.8.0...v2.9.0)

Enhancements

* Support for "X minutes X seconds" spec run duration in formatter. (uzzz)
* Strip whitespace from group and example names in doc formatter.
* Removed spork-0.9 shim. If you're using spork-0.8.x, you'll need to upgrade
  to 0.9.0.

Bug fixes

* Restore `--full_backtrace` option
* Ensure that values passed to `config.filter_run` are respected when running
  over DRb (using spork).
* Ensure shared example groups are reset after a run (as example groups are).
* Remove `rescue false` from calls to filters represented as Procs
* Ensure `described_class` gets the closest constant (pyromaniac)
* In "autorun", don't run the specs in the `at_exit` hook if there was an
  exception (most likely due to a SyntaxError). (sunaku)
* Don't extend groups with modules already used to extend ancestor groups.
* `its` correctly memoizes nil or false values (Yamada Masaki)

### 2.8.0 / 2012-01-04

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.8.0.rc2...v2.8.0)

Bug fixes

* For metadata filtering, restore passing the entire array to the proc, rather
  than each item in the array (weidenfreak)
* Ensure each spec file is loaded only once
    * Fixes a bug that caused all the examples in a file to be run when
      referenced twice with line numbers in a command, e.g.
        * `rspec path/to/file:37 path/to/file:42`

### 2.8.0.rc2 / 2011-12-19

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.8.0.rc1...v2.8.0.rc2)

Enhancments

* new `--init` command (Peter Schröder)
    * generates `spec/spec_helper.rb`
    * deletes obsolete files (on confirmation)
    * merged with and deprecates `--configure` command, which generated
      `.rspec`
* use `require_relative` when available (Ian Leitch)
* `include_context` and `include_examples` accept params (Calvin Bascom)
* print the time for every example in the html formatter (Richie Vos)
* several tasty refactoring niblets (Sasha)
* `it "does something", :x => [:foo,'bar',/baz/] (Ivan Neverov)
    * supports matching n command line tag values with an example or group

### 2.8.0.rc1 / 2011-11-06

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.7.1...v2.8.0.rc1)

Enhancements

* `--order` (Justin Ko)
    * run examples in random order: `--order rand`
    * specify the seed: `--order rand:123`
* `--seed SEED`
    * equivalent of `--order rand:SEED`
* SharedContext supports `let` (David Chelimsky)
* Filter improvements (David Chelimsky)
    * override opposing tags from the command line
    * override RSpec.configure tags from the command line
    * `--line_number 37` overrides all other filters
    * `path/to/file.rb:37` overrides all other filters
    * refactor: consolidate filter management in a FilterManger object
* Eliminate Ruby warnings (Matijs van Zuijlen)
* Make reporter.report an API (David Chelimsky)
    * supports extension tools like interative_rspec

Changes

* change `config.color_enabled` (getter/setter/predicate) to `color` to align
  with `--[no]-color` CLI option.
    * `color_enabled` is still supported for now, but will likley be deprecated
      in a 2.x release so we can remove it in 3.0.

Bug fixes

* Make sure the `bar` in `--tag foo:bar` makes it to DRb (Aaron Gibralter)
* Fix bug where full descriptions of groups nested 3 deep  were repeated.
* Restore report of time to run to start after files are loaded.
    * fixes bug where run times were cumalitive in spork
    * fixes compatibility with time-series metrics
* Don't error out when `config.mock_with` or `expect_with` is re-specifying the
  current config (Myron Marston)

* Deprecations
    * :alias option on `configuration.add_setting`. Use `:alias_with` on the
      original setting declaration instead.

### 2.7.1 / 2011-10-20

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.7.0...v2.7.1)

Bug fixes

* tell autotest the correct place to find the rspec executable

### 2.7.0 / 2011-10-16

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.6.4...v2.7.0)

NOTE: RSpec's release policy dictates that there should not be any backward
incompatible changes in minor releases, but we're making an exception to
release a change to how RSpec interacts with other command line tools.

As of 2.7.0, you must explicity `require "rspec/autorun"` unless you use the
`rspec` command (which already does this for you).

Enhancements

* Add `example.exception` (David Chelimsky)
* `--default_path` command line option (Justin Ko)
* support multiple `--line_number` options (David J. Hamilton)
    * also supports `path/to/file.rb:5:9` (runs examples on lines 5 and 9)
* Allow classes/modules to be used as shared example group identifiers (Arthur
  Gunn)
* Friendly error message when shared context cannot be found (Sławosz
  Sławiński)
* Clear formatters when resetting config (John Bintz)
* Add `xspecify` and xexample as temp-pending methods (David Chelimsky)
* Add `--no-drb` option (Iain Hecker)
* Provide more accurate run time by registering start time before code is
  loaded (David Chelimsky)
    * reverted in 2.8.0
* Rake task default pattern finds specs in symlinked dirs (Kelly Felkins)
* Rake task no longer does anything to invoke bundler since Bundler already
  handles it for us. Thanks to Andre Arko for the tip.
* Add `--failure-exit-code` option (Chris Griego)

Bug fixes

* Include `Rake::DSL` to remove deprecation warnings in Rake > 0.8.7 (Pivotal
  Casebook)
* Only eval `let` block once even if it returns `nil` (Adam Meehan)
* Fix `--pattern` option (wasn't being recognized) (David Chelimsky)
* Only implicitly `require "rspec/autorun"` with the `rspec` command (David
  Chelimsky)
* Ensure that rspec's `at_exit` defines the exit code (Daniel Doubrovkine)
* Show the correct snippet in the HTML and TextMate formatters (Brian Faherty)

### 2.6.4 / 2011-06-06

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.6.3...v2.6.4)

NOTE: RSpec's release policy dictates that there should not be new
functionality in patch releases, but this minor enhancement slipped in by
accident.  As it doesn't add a new API, we decided to leave it in rather than
roll back this release.

Enhancements

* Add summary of commands to run individual failed examples.

Bug fixes

* Support exclusion filters in DRb. (Yann Lugrin)
* Fix --example escaping when run over DRb. (Elliot Winkler)
* Use standard ANSI codes for color formatting so colors work in a wider set of
  color schemes.

### 2.6.3 / 2011-05-24

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.6.2...v2.6.3)

Bug fixes

* Explicitly convert exit code to integer, avoiding TypeError when return
  value of run is IO object proxied by `DRb::DRbObject` (Julian Scheid)
* Clarify behavior of `--example` command line option
* Build using a rubygems-1.6.2 to avoid downstream yaml parsing error

### 2.6.2 / 2011-05-21

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.6.1...v2.6.2)

Bug fixes

* Warn rather than raise when HOME env var is not defined
* Properly merge command-line exclusions with default :if and :unless (joshcooper)

### 2.6.1 / 2011-05-19

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.6.0...v2.6.1)

Bug fixes

* Don't extend nil when filters are nil
* `require 'rspec/autorun'` when running rcov.

### 2.6.0 / 2011-05-12

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.5.1...v2.6.0)

Enhancements

* `shared_context` (Damian Nurzynski)
    * extend groups matching specific metadata with:
        * method definitions
        * subject declarations
        * let/let! declarations
        * etc (anything you can do in a group)
* `its([:key])` works for any subject with #[]. (Peter Jaros)
* `treat_symbols_as_metadata_keys_with_true_values` (Myron Marston)
* Print a deprecation warning when you configure RSpec after defining an
  example.  All configuration should happen before any examples are defined.
  (Myron Marston)
* Pass the exit status of a DRb run to the invoking process. This causes specs
  run via DRb to not just return true or false. (Ilkka Laukkanen)
* Refactoring of `ConfigurationOptions#parse_options` (Rodrigo Rosenfeld Rosas)
* Report excluded filters in runner output (tip from andyl)
* Clean up messages for filters/tags.
* Restore --pattern/-P command line option from rspec-1
* Support false as well as true in config.full_backtrace= (Andreas Tolf
  Tolfsen)

Bug fixes

* Don't stumble over an exception without a message (Hans Hasselberg)
* Remove non-ascii characters from comments that were choking rcov (Geoffrey
  Byers)
* Fixed backtrace so it doesn't include lines from before the autorun at_exit
  hook (Myron Marston)
* Include RSpec::Matchers when first example group is defined, rather than just
  before running the examples.  This works around an obscure bug in ruby 1.9
  that can cause infinite recursion. (Myron Marston)
* Don't send `example_group_[started|finished]` to formatters for empty groups.
* Get specs passing on jruby (Sidu Ponnappa)
* Fix bug where mixing nested groups and outer-level examples gave
  unpredictable :line_number behavior (Artur Małecki)
* Regexp.escape the argument to --example (tip from Elliot Winkler)
* Correctly pass/fail pending block with message expectations
* CommandLine returns exit status (0/1) instead of true/false
* Create path to formatter output file if it doesn't exist (marekj).


### 2.5.1 / 2011-02-06

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.5.0...v2.5.1)

NOTE: this release breaks compatibility with rspec/autotest/bundler
integration, but does so in order to greatly simplify it.

With this release, if you want the generated autotest command to include
'bundle exec', require Autotest's bundler plugin in a .autotest file in the
project's root directory or in your home directory:

    require "autotest/bundler"

Now you can just type 'autotest' on the command line and it will work as you expect.

If you don't want 'bundle exec', there is nothing you have to do.

### 2.5.0 / 2011-02-05

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.4.0...v2.5.0)

Enhancements

* Autotest::Rspec2 parses command line args passed to autotest after '--'
* --skip-bundler option for autotest command
* Autotest regexp fixes (Jon Rowe)
* Add filters to html and textmate formatters (Daniel Quimper)
* Explicit passing of block (need for JRuby 1.6) (John Firebaugh)

Bug fixes

* fix dom IDs in HTML formatter (Brian Faherty)
* fix bug with --drb + formatters when not running in drb
* include --tag options in drb args (monocle)
* fix regression so now SPEC_OPTS take precedence over CLI options again (Roman
  Chernyatchik)
* only call its(:attribute) once (failing example from Brian Dunn)
* fix bizarre bug where rspec would hang after String.alias :to_int :to_i
  (Damian Nurzynski)

Deprecations

* implicit inclusion of 'bundle exec' when Gemfile present (use autotest's
  bundler plugin instead)

### 2.4.0 / 2011-01-02

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.3.1...v2.4.0)

Enhancements

* start the debugger on -d so the stack trace is visible when it stops
  (Clifford Heath)
* apply hook filtering to examples as well as groups (Myron Marston)
* support multiple formatters, each with their own output
* show exception classes in failure messages unless they come from RSpec
  matchers or message expectations
* before(:all) { pending } sets all examples to pending

Bug fixes

* fix bug due to change in behavior of reject in Ruby 1.9.3-dev (Shota
  Fukumori)
* fix bug when running in jruby: be explicit about passing block to super (John
  Firebaugh)
* rake task doesn't choke on paths with quotes (Janmejay Singh)
* restore --options option from rspec-1
* require 'ostruct' to fix bug with its([key]) (Kim Burgestrand)
* --configure option generates .rspec file instead of autotest/discover.rb

### 2.3.1 / 2010-12-16

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.3.0...v2.3.1)

Bug fixes

* send debugger warning message to $stdout if RSpec.configuration.error_stream
  has not been defined yet.
* HTML Formatter _finally_ properly displays nested groups (Jarmo Pertman)
* eliminate some warnings when running RSpec's own suite (Jarmo Pertman)

### 2.3.0 / 2010-12-12

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.2.1...v2.3.0)

Enhancements

* tell autotest to use "rspec2" if it sees a .rspec file in the project's root
  directory
    * replaces the need for ./autotest/discover.rb, which will not work with
      all versions of ZenTest and/or autotest
* config.expect_with
    * :rspec          # => rspec/expectations
    * :stdlib         # => test/unit/assertions
    * :rspec, :stdlib # => both

Bug fixes

* fix dev Gemfile to work on non-mac-os machines (Lake Denman)
* ensure explicit subject is only eval'd once (Laszlo Bacsi)

### 2.2.1 / 2010-11-28

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.2.0...v2.2.1)

Bug fixes
* alias_method instead of override Kernel#method_missing (John Wilger)
* changed --autotest to --tty in generated command (MIKAMI Yoshiyuki)
* revert change to debugger (had introduced conflict with Rails)
    * also restored --debugger/-debug option

### 2.2.0 / 2010-11-28

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.1.0...v2.2.0)

Deprecations/changes

* --debug/-d on command line is deprecated and now has no effect
* win32console is now ignored; Windows users must use ANSICON for color support
  (Bosko Ivanisevic)

Enhancements

* When developing locally rspec-core now works with the rspec-dev setup or your
  local gems
* Raise exception with helpful message when rspec-1 is loaded alongside rspec-2
  (Justin Ko)
* debugger statements _just work_ as long as ruby-debug is installed
  * otherwise you get warned, but not fired
* Expose example.metadata in around hooks
* Performance improvments (much faster now)

Bug fixes

* Make sure --fail-fast makes it across drb
* Pass -Ilib:spec to rcov

### 2.1.0 / 2010-11-07

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.0.1...v2.1.0)

Enhancments

* Add skip_bundler option to rake task to tell rake task to ignore the presence
  of a Gemfile (jfelchner)
* Add gemfile option to rake task to tell rake task what Gemfile to look for
  (defaults to 'Gemfile')
* Allow passing caller trace into Metadata to support extensions (Glenn
  Vanderburg)
* Add deprecation warning for Spec::Runner.configure to aid upgrade from
  RSpec-1
* Add deprecated Spec::Rake::SpecTask to aid upgrade from RSpec-1
* Add 'autospec' command with helpful message to aid upgrade from RSpec-1
* Add support for filtering with tags on CLI (Lailson Bandeira)
* Add a helpful message about RUBYOPT when require fails in bin/rspec (slyphon)
* Add "-Ilib" to the default rcov options (Tianyi Cui)
* Make the expectation framework configurable (default rspec, of course)
  (Justin Ko)
* Add 'pending' to be conditional (Myron Marston)
* Add explicit support for :if and :unless as metadata keys for conditional run
  of examples (Myron Marston)
* Add --fail-fast command line option (Jeff Kreeftmeijer)

Bug fixes

* Eliminate stack overflow with "subject { self }"
* Require 'rspec/core' in the Raketask (ensures it required when running rcov)

### 2.0.1 / 2010-10-18

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.0.0...v2.0.1)

Bug fixes

* Restore color when using spork + autotest
* Pending examples without docstrings render the correct message (Josep M.
  Bach)
* Fixed bug where a failure in a spec file ending in anything but _spec.rb
  would fail in a confusing way.
* Support backtrace lines from erb templates in html formatter (Alex Crichton)

### 2.0.0 / 2010-10-10

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.0.0.rc...v2.0.0)

RSpec-1 compatibility

* Rake task uses ENV["SPEC"] as file list if present

Bug fixes

* Bug Fix: optparse --out foo.txt (Leonardo Bessa)
* Suppress color codes for non-tty output (except autotest)

### 2.0.0.rc / 2010-10-05

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.0.0.beta.22...v2.0.0.rc)

Enhancements

* implicitly require unknown formatters so you don't have to require the file
  explicitly on the command line (Michael Grosser)
* add --out/-o option to assign output target
* added fail_fast configuration option to abort on first failure
* support a Hash subject (its([:key]) { should == value }) (Josep M. Bach)

Bug fixes

* Explicitly require rspec version to fix broken rdoc task (Hans de Graaff)
* Ignore backtrace lines that come from other languages, like Java or
  Javascript (Charles Lowell)
* Rake task now does what is expected when setting (or not setting)
  fail_on_error and verbose
* Fix bug in which before/after(:all) hooks were running on excluded nested
  groups (Myron Marston)
* Fix before(:all) error handling so that it fails examples in nested groups,
  too (Myron Marston)

### 2.0.0.beta.22 / 2010-09-12

[Full Changelog](http://github.com/rspec/rspec-core/compare/v2.0.0.beta.20...v2.0.0.beta.22)

Enhancements

* removed at_exit hook
* CTRL-C stops the run (almost) immediately
    * first it cleans things up by running the appropriate after(:all) and
      after(:suite) hooks
    * then it reports on any examples that have already run
* cleaned up rake task
    * generate correct task under variety of conditions
    * options are more consistent
    * deprecated redundant options
* run 'bundle exec autotest' when Gemfile is present
* support ERB in .rspec options files (Justin Ko)
* depend on bundler for development tasks (Myron Marston)
* add example_group_finished to formatters and reporter (Roman Chernyatchik)

Bug fixes

* support paths with spaces when using autotest (Andreas Neuhaus)
* fix module_exec with ruby 1.8.6 (Myron Marston)
* remove context method from top-level
    * was conflicting with irb, for example
* errors in before(:all) are now reported correctly (Chad Humphries)

Removals

* removed -o --options-file command line option
    * use ./.rspec and ~/.rspec
