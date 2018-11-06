### 3.8.2 / 2018-10-09
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.8.1...v3.8.2)

Bug Fixes:

* Change `include` matcher to rely on a `respond_to?(:include?)` check rather than a direct
  Hash comparison before calling `to_hash` to convert to a hash. (Jordan Owens, #1073)
* Prevent unexpected call stack jumps from causing an obscure error (`IndexError`), and
  replace that error with a proper informative message. (Jon Rowe, #1076)

### 3.8.1 / 2018-08-06
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.8.0...v3.8.1)

Bug Fixes:

* Fix regression in `include` matcher so stopped
  `expect(hash.with_indifferent_access).to include(:symbol_key)`
  from working. (Eito Katagiri, #1069)

### 3.8.0 / 2018-08-04
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.7.0...v3.8.0)

Enhancements:

* Improve failure message of `change(receiver, :message)` by including the
  receiver as `SomeClass#some_message`. (Tomohiro Hashidate, #1005)
* Improve `change` matcher so that it can correctly detect changes in
  deeply nested mutable objects (such as arrays-of-hashes-of-arrays).
  The improved logic uses the before/after `hash` value to see if the
  object has been mutated, rather than shallow duping the object.
  (Myron Marston, #1034)
* Improve `include` matcher so that pseudo-hash objects (e.g. objects
  that decorate a hash using a `SimpleDelegator` or similar) are treated
  as a hash, as long as they implement `to_hash`. (Pablo Brasero, #1012)
* Add `max_formatted_output_length=` to configuration, allowing changing
  the length at which we truncate large output strings.
  (Sam Phippen #951, Benoit Tigeot #1056)
* Improve error message when passing a matcher that doesn't support block
  expectations to a block based `expect`. (@nicktime, #1066)

### 3.7.0 / 2017-10-17
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.6.0...v3.7.0)

Enhancements:

* Improve compatibility with `--enable-frozen-string-literal` option
  on Ruby 2.3+. (Pat Allan, #997)

### 3.6.0 / 2017-05-04
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.6.0.beta2...v3.6.0)

Enhancements:

* Treat NoMethodError as a failure for comparison matchers. (Jon Rowe, #972)
* Allow for scoped aliased and negated matchers--just call
  `alias_matcher` or `define_negated_matcher` from within an example
  group. (Markus Reiter, #974)
* Improve failure message of `change` matcher with block and `satisfy` matcher
  by including the block snippet instead of just describing it as `result` or
  `block` when Ripper is available. (Yuji Nakayama, #987)

Bug Fixes:

* Fix `yield_with_args` and `yield_successive_args` matchers so that
  they compare expected to actual args at the time the args are yielded
  instead of at the end, in case the method that is yielding mutates the
  arguments after yielding. (Alyssa Ross, #965)

### 3.6.0.beta2 / 2016-12-12
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.6.0.beta1...v3.6.0.beta2)

Bug Fixes:

* Using the exist matcher on `File` no longer produces a deprecation warning.
  (Jon Rowe, #954)

### 3.6.0.beta1 / 2016-10-09
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.5.0...v3.6.0.beta1)

Bug Fixes:

* Fix `contain_exactly` to work correctly with ranges. (Myron Marston, #940)
* Fix `change` to work correctly with sets. (Marcin Gajewski, #939)

### 3.5.0 / 2016-07-01
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.5.0.beta4...v3.5.0)

Enhancements:

* Add support for keyword arguments to the `respond_to` matcher. (Rob Smith, #915).

### 3.5.0.beta4 / 2016-06-05
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.5.0.beta3...v3.5.0.beta4)

Bug Fixes:

* Fix `include` matcher so that it provides a valid diff for hashes. (Yuji Nakayama, #916)

### 3.5.0.beta3 / 2016-04-02
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.5.0.beta2...v3.5.0.beta3)

Enhancements:

* Make `rspec/expectations/minitest_integration` work on Minitest::Spec
  5.6+. (Myron Marston, #904)
* Add an alias `having_attributes` for `have_attributes` matcher.
  (Yuji Nakayama, #905)
* Improve `change` matcher error message when block is mis-used.
  (Alex Altair, #908)

### 3.5.0.beta2 / 2016-03-10
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.5.0.beta1...v3.5.0.beta2)

Enhancements:

* Add the ability to raise an error on encountering false positives via
  `RSpec::Configuration#on_potential_false_positives = :raise`. (Jon Rowe, #900)
* When using the custom matcher DSL, support new
  `notify_expectation_failures: true` option for the `match` method to
  allow expectation failures to be raised as normal instead of being
  converted into a `false` return value for `matches?`. (Jon Rowe, #892)

Bug Fixes:

* Allow `should` deprecation check to work on `BasicObject`s. (James Coleman, #898)

### 3.5.0.beta1 / 2016-02-06
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.4.0...v3.5.0.beta1)

Enhancements:

* Make `match_when_negated` in custom matcher DSL support use of
  expectations within the match logic. (Chris Arcand, #789)

Bug Fixes:

* Return `true` as expected from passing negated expectations
  (such as `expect("foo").not_to eq "bar"`), so they work
  properly when used within a `match` or `match_when_negated`
  block. (Chris Arcand, #789)

### 3.4.0 / 2015-11-11
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.3.1...v3.4.0)

Enhancements:

* Warn when `RSpec::Matchers` is included in a superclass after it has
  already been included in a subclass on MRI 1.9, since that situation
  can cause uses of `super` to trigger infinite recursion. (Myron Marston, #816)
* Stop rescuing `NoMemoryError`, `SignalExcepetion`, `Interrupt` and
  `SystemExit`. It is dangerous to interfere with these. (Myron Marston, #845)
* Add `#with_captures` to the
  [match matcher](https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers/match-matcher)
  which allows a user to specify expected captures when matching a regex
  against a string. (Sam Phippen, #848)
* Always print compound failure messages in the multi-line form. Trying
  to print it all on a single line didn't read very well. (Myron Marston, #859)

Bug Fixes:

* Fix failure message from dynamic predicate matchers when the object
  does not respond to the predicate so that it is inspected rather
  than relying upon its `to_s` -- that way for `nil`, `"nil"` is
  printed rather than an empty string. (Myron Marston, #841)
* Fix SystemStackError raised when diffing an Enumerable object
  whose `#each` includes the object itself. (Yuji Nakayama, #857)

### 3.3.1 / 2015-07-15
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.3.0...v3.3.1)

Bug Fixes:

* Fix `be >`, `be <`, etc so that it fails rather than allowing an
  argument error to be raised when compared against an object of the
  wrong type. This allows it to be used in composed matcher expressions
  against heterogeneous objects. (Dennis Günnewig, #809)
* Fix `respond_to` to work properly on target objects
  that redefine the `method` method. (unmanbearpig, #821)

### 3.3.0 / 2015-06-12
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.2.1...v3.3.0)

Enhancements:

* Expose `RSpec::Matchers::EnglishPhrasing` to make it easier to write
  nice failure messages in custom matchers. (Jared Beck, #736)
* Add `RSpec::Matchers::FailMatchers`, a mixin which provides
  `fail`, `fail_with` and `fail_including` matchers for use in
  specifying that an expectation fails for use by
  extension/plugin authors. (Charlie Rudolph, #729)
* Avoid loading `tempfile` (and its dependencies) unless
  it is absolutely needed. (Myron Marston, #735)
* Improve failure output when attempting to use `be_true` or `be_false`.
  (Tim Wade, #744)
* Define `RSpec::Matchers#respond_to_missing?` so that
  `RSpec::Matchers#respond_to?` and `RSpec::Matchers#method` handle
  dynamic predicate matchers. (Andrei Botalov, #751)
* Use custom Time/DateTime/BigDecimal formatting for all matchers
  so they are consistently represented in failure messages.
  (Gavin Miller, #740)
* Add configuration to turn off warnings about matcher combinations that
  may cause false positives. (Jon Rowe, #768)
* Warn when using a bare `raise_error` matcher that you may be subject to
  false positives. (Jon Rowe, #768)
* Warn rather than raise when using the`raise_error` matcher in negative
  expectations that may be subject to false positives. (Jon Rowe, #775)
* Improve failure message for `include(a, b, c)` so that if `a` and `b`
  are included the failure message only mentions `c`. (Chris Arcand, #780)
* Allow `satisfy` matcher to take an optional description argument
  that will be used in the `description`, `failure_message` and
  `failure_message_when_negated` in place of the undescriptive
  "sastify block". (Chris Arcand, #783)
* Add new `aggregate_failures` API that allows multiple independent
  expectations to all fail and be listed in the failure output, rather
  than the example aborting on the first failure. (Myron Marston, #776)
* Improve `raise_error` matcher so that it can accept a matcher as a single argument
  that matches the message. (Time Wade, #782)

Bug Fixes:

* Make `contain_exactly` / `match_array` work with strict test doubles
  that have not defined `<=>`. (Myron Marston, #758)
* Fix `include` matcher so that it omits the diff when it would
  confusingly highlight items that are actually included but are not
  an exact match in a line-by-line diff. (Tim Wade, #763)
* Fix `match` matcher so that it does not blow up when matching a string
  or regex against another matcher (rather than a string or regex).
  (Myron Marston, #772)
* Silence whitespace-only diffs. (Myron Marston, #801)

### 3.2.1 / 2015-04-06
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.2.0...v3.2.1)

Bug Fixes:

* Prevent `Range`s from being enumerated when generating matcher
  descriptions. (Jon Rowe, #755)
* Ensure exception messages are compared as strings in the `raise_error`
  matcher. (Jon Rowe, #755)

### 3.2.0 / 2015-02-03
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.1.2...v3.2.0)

Enhancements:

* Add `block_arg` method to custom matcher API, which allows you to
  access the block passed to a custom matcher, if there is one.
  (Mike Dalton, #645)
* Provide more detail in failure message of `yield_control` matcher.
  (Jon Rowe, #650)
* Add a shorthand syntax for `chain` in the matcher DSL which assigns values
  for use elsewhere, for example `chain :and_smaller_than, :small_value`
  creates an `attr_reader` for `small_value` (Tom Stuart, #644)
* Provide a more helpful deprecation message when using the `should` syntax.
  (Elia Schito, #663)
* Provide more detail in the `have_attributes` matcher failure message.
  (Jon Rowe,  #668)
* Make the `have_attributes` matcher diffable.
  (Jon Rowe, Alexey Fedorov, #668)
* Add `output(...).to_std(out|err)_from_any_process` as alternatives
  to `output(...).to_std(out|err)`. The latter doesn't work when a sub
  process writes to the named stream but is much faster.
  (Alex Genco, #700)
* Improve compound matchers (created by `and` and `or`) so that diffs
  are included in failures when one or more of their matchers
  are diffable. (Alexey Fedorov, #713)

Bug Fixes:

* Avoid calling `private_methods` from the `be` predicate matcher on
  the target object if the object publicly responds to the predicate
  method. This avoids a possible error that can occur if the object
  raises errors from `private_methods` (which can happen with celluloid
  objects). (@chapmajs, #670)
* Make `yield_control` (with no modifier) default to
  `at_least(:once)` rather than raising a confusing error
  when multiple yields are encountered.
  (Myron Marston, #675)
* Fix "instance variable @color not initialized" warning when using
  rspec-expectations outside of an rspec-core context. (Myron Marston, #689)
* Fix `start_with` and `end_with` to work properly when checking a
  string against an array of strings. (Myron Marston, #690)
* Don't use internally delegated matchers when generating descriptions
  for examples without doc strings. (Myron Marston, #692)

### 3.1.2 / 2014-09-26
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.1.1...v3.1.2)

Bug Fixes:

* Fix `define_negated_matcher` so that matchers that support fluent
  interfaces continue to be negated after you use the chained method.
  (Myron Marston, #656)
* Fix `define_negated_matcher` so that the matchers fail with an
  appropriate failure message. (Myron Marston, #659)

### 3.1.1 / 2014-09-15
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.1.0...v3.1.1)

Bug Fixes:

* Fix regression in `all` matcher in 3.1.0 that prevented it from
  working on objects that are not `Enumerable` but do implement
  `each_with_index` (such as an ActiveRecord proxy). (Jori Hardman, #647)

### 3.1.0 / 2014-09-04
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.4...v3.1.0)

Enhancements:

* Add `have_attributes` matcher, that passes if actual's attribute
  values match the expected attributes hash:
  `Person = Struct.new(:name, :age)`
  `person = Person.new("Bob", 32)`
  `expect(person).to have_attributes(:name => "Bob", :age => 32)`.
  (Adam Farhi, #571)
* Extended compound matcher support to block matchers, for cases like:
  `expect { ... }.to change { x }.to(3).and change { y }.to(4)`. (Myron
  Marston, #567)
* Include chained methods in custom matcher description and failure message
  when new `include_chain_clauses_in_custom_matcher_descriptions` config
  option is enabled. (Dan Oved, #600)
* Add `thrice` modifier to `yield_control` matcher as a synonym for
  `exactly(3).times`. (Dennis Taylor, #615)
* Add `RSpec::Matchers.define_negated_matcher`, which defines a negated
  version of the named matcher. (Adam Farhi, Myron Marston, #618)
* Document and support negation of `contain_exactly`/`match_array`.
  (Jon Rowe, #626).

Bug Fixes:

* Rename private `LegacyMacherAdapter` constant to `LegacyMatcherAdapter`
  to fix typo. (Abdelkader Boudih, #563)
* Fix `all` matcher so that it fails properly (rather than raising a
  `NoMethodError`) when matched against a non-enumerable. (Hao Su, #622)

### 3.0.4 / 2014-08-14
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.3...v3.0.4)

Bug Fixes:

* Fix `start_with` and `end_with` so that they work properly with
  structs. (Myron Marston, #620)
* Fix failure message generation so that structs are printed properly
  in failures. Previously failure messages would represent them as
  an array. (Myron Marston, #620)
* Fix composable matcher support so that it does not wrongly treat
  structs as arrays. (Myron Marston, #620)

### 3.0.3 / 2014-07-21
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.2...v3.0.3)

Bug Fixes:

* Fix issue with detection of generic operator matchers so they work
  correctly when undefined. (Myron Marston, #597)
* Don't inadvertently define `BasicObject` in 1.8.7. (Chris Griego, #603)
* Fix `include` matcher so that it fails gracefully when matched against
  an object that does not respond to `include?`. (Myron Marston, #607)

### 3.0.2 / 2014-06-19
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.1...v3.0.2)

Bug Fixes:

* Fix regression in `contain_exactly` (AKA `match_array`) that caused it
  to wrongly pass when the expected array was empty. (Myron Marston, #581)
* Provide a better error message when you use the `change(obj, :msg)`
  form of the change matcher but forget the message argument. (Alex
  Sunderland, #585)
* Make the `contain_exactly` matcher work with arrays that contain hashes in
  arbitrary ordering. (Sam Phippen, #578)

### 3.0.1 / 2014-06-12
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.0...v3.0.1)

Bug Fixes:

* Add a missing `require` that would cause the `respond_to` matcher to
  fail when used in a project where the rest of RSpec (e.g. core and
  expecatations) weren't being used. (Myron Marston, #566)
* Structs are no longer treated as arrays when diffed. (Jon Rowe, #576)

### 3.0.0 / 2014-06-01
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.0.rc1...v3.0.0)

No code changes. Just taking it out of pre-release.

### 3.0.0.rc1 / 2014-05-18
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.0.beta2...v3.0.0.rc1)

Breaking Changes for 3.0.0:

* Remove `matcher_execution_context` attribute from DSL-defined
  custom matchers. (Myron Marston)
* Remove `RSpec::Matchers::Pretty#_pretty_print`. (Myron Marston)
* Remove `RSpec::Matchers::Pretty#expected_to_sentence`. (Myron Marston)
* Rename `RSpec::Matchers::Configuration` constant to
  `RSpec::Expectations::Configuration`. (Myron Marston)
* Prevent `have_xyz` predicate matchers using private methods.
  (Adrian Gonzalez)
* Block matchers must now implement `supports_block_expectations?`.
  (Myron Marston)
* Stop supporting `require 'rspec-expectations'`.
  Use `require 'rspec/expectations'` instead. (Myron Marston)

Bug Fixes:

* Fix `NoMethodError` triggered by beta2 when `YARD` was loaded in
  the test environment. (Myron Marston)
* Fix `be_xyz` matcher to accept a `do...end` block. (Myron Marston)
* Fix composable matcher failure message generation logic
  so that it does not blow up when given `$stdout` or `$stderr`.
  (Myron Marston)
* Fix `change` matcher to work properly with `IO` objects.
  (Myron Marston)
* Fix `exist` matcher so that it can be used in composed matcher
  expressions involving objects that do not implement `exist?` or
  `exists?`. (Daniel Fone)
* Fix composable matcher match logic so that it clones matchers
  before using them in order to work properly with matchers
  that use internal memoization based on a given `actual` value.
  (Myron Marston)
* Fix `be_xyz` and `has_xyz` predicate matchers so that they can
  be used in composed matcher expressions involving objects that
  do not implement the predicate method. (Daniel Fone)

Enhancements:

* Document the remaining public APIs. rspec-expectations now has 100% of
  the public API documented and will remain that way (as new undocumented
  methods will fail the build). (Myron Marston)
* Improve the formatting of BigDecimal objects in `eq` matcher failure
  messages. (Daniel Fone)
* Improve the failure message for `be_xyz` predicate matchers so
  that it includes the `inspect` output of the receiver.
  (Erik Michaels-Ober, Sam Phippen)
* Add `all` matcher, to allow you to specify that a given matcher
  matches all elements in a collection:
  `expect([1, 3, 5]).to all( be_odd )`. (Adam Farhi)
* Add boolean aliases (`&`/`|`) for compound operators (`and`/`or`). (Adam Farhi)
* Give users a clear error when they wrongly use a value matcher
  in a block expectation expression (e.g. `expect { 3 }.to eq(3)`)
  or vice versa.  (Myron Marston)

### 3.0.0.beta2 / 2014-02-17
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v3.0.0.beta1...v3.0.0.beta2)

Breaking Changes for 3.0.0:

* Remove deprecated support for accessing the `RSpec` constant using
  `Rspec` or `Spec`. (Myron Marston)
* Remove deprecated `RSpec::Expectations.differ=`. (Myron Marston)
* Remove support for deprecated `expect(...).should`. (Myron Marston)
* Explicitly disallow `expect { }.not_to change { }` with `by`,
  `by_at_least`, `by_at_most` or `to`. These have never been supported
  but did not raise explicit errors. (Myron Marston)
* Provide `===` rather than `==` as an alias of `matches?` for
  all matchers.  The semantics of `===` are closer to an RSpec
  matcher than `==`. (Myron Marston)
* Remove deprecated `RSpec::Matchers::OperatorMatcher` constant.
  (Myron Marston)
* Make `RSpec::Expectations::ExpectationNotMetError` subclass
  `Exception` rather than `StandardError` so they can bypass
  a bare `rescue` in end-user code (e.g. when an expectation is
  set from within a rspec-mocks stub implementation). (Myron Marston)
* Remove Test::Unit and Minitest 4.x integration. (Myron Marston)

Enhancements:

* Simplify the failure message of the `be` matcher when matching against:
  `true`, `false` and `nil`. (Sam Phippen)
* Update matcher protocol and custom matcher DSL to better align
  with the newer `expect` syntax. If you want your matchers to
  maintain compatibility with multiple versions of RSpec, you can
  alias the new names to the old. (Myron Marston)
    * `failure_message_for_should` => `failure_message`
    * `failure_message_for_should_not` => `failure_message_when_negated`
    * `match_for_should` => `match`
    * `match_for_should_not` => `match_when_negated`
* Improve generated descriptions from `change` matcher. (Myron Marston)
* Add support for compound matcher expressions using `and` and `or`.
  Simply chain them off of any existing matcher to create an expression
  like `expect(alphabet).to start_with("a").and end_with("z")`.
  (Eloy Espinaco)
* Add `contain_exactly` as a less ambiguous version of `match_array`.
  Note that it expects the expected array to be splatted as
  individual args: `expect(array).to contain_exactly(1, 2)` is
  the same as `expect(array).to match_array([1, 2])`. (Myron Marston)
* Update `contain_exactly`/`match_array` so that it can match against
  other non-array collections (such as a `Set`). (Myron Marston)
* Update built-in matchers so that they can accept matchers as arguments
  to allow you to compose matchers in arbitrary ways. (Myron Marston)
* Add `RSpec::Matchers::Composable` mixin that can be used to make
  a custom matcher composable as well. Note that custom matchers
  defined via `RSpec::Matchers.define` already have this. (Myron
  Marston)
* Define noun-phrase aliases for built-in matchers, which can be
  used when creating composed matcher expressions that read better
  and provide better failure messages. (Myron Marston)
* Add `RSpec::Matchers.alias_matcher` so users can define their own
  matcher aliases. The `description` of the matcher will reflect the
  alternate matcher name. (Myron Marston)
* Add explicit `be_between` matcher. `be_between` has worked for a
  long time as a dynamic predicate matcher, but the failure message
  was suboptimal. The new matcher provides a much better failure
  message. (Erik Michaels-Ober)
* Enhance the `be_between` matcher to allow for `inclusive` or `exclusive`
  comparison (e.g. inclusive of min/max or exclusive of min/max).
  (Pedro Gimenez)
* Make failure message for `not_to be #{operator}` less confusing by
  only saying it's confusing when comparison operators are used.
  (Prathamesh Sonpatki)
* Improve failure message of `eq` matcher when `Time` or `DateTime`
  objects are used so that the full sub-second precision is included.
  (Thomas Holmes, Jeff Wallace)
* Add `output` matcher for expecting that a block outputs `to_stdout`
  or `to_stderr`. (Luca Pette, Matthias Günther)
* Forward a provided block on to the `has_xyz?` method call when
  the `have_xyz` matcher is used. (Damian Galarza)
* Provide integration with Minitest 5.x. Require
  `rspec/expectations/minitest_integration` after loading minitest
  to use rspec-expectations with minitest. (Myron Marston)

Bug Fixes:

* Fix wrong matcher descriptions with falsey expected value (yujinakayama)
* Fix `expect { }.not_to change { }.from(x)` so that the matcher only
  passes if the starting value is `x`. (Tyler Rick, Myron Marston)
* Fix hash diffing, so that it colorizes properly and doesn't consider trailing
  commas when performing the diff. (Jared Norman)
* Fix built-in matchers to fail normally rather than raising
  `ArgumentError` when given an object of the wrong type to match
  against, so that they work well in composite matcher expressions like
  `expect([1.51, "foo"]).to include(a_string_matching(/foo/), a_value_within(0.1).of(1.5))`.
  (Myron Marston)

Deprecations:

* Retain support for RSpec 2 matcher protocol (e.g. for matchers
  in 3rd party extension gems like `shoulda`), but it will print
  a deprecation warning. (Myron Marston)

### 3.0.0.beta1 / 2013-11-07
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.99.2...v3.0.0.beta1)

Breaking Changes for 3.0.0:

* Remove explicit support for 1.8.6. (Jon Rowe)
* Remove the deprecated `be_close` matcher, preferring `be_within` instead.
  (Sam Phippen)
* Remove the deprecated `have`, `have_at_least` and `have_at_most` matchers.
  You can continue using those matchers through https://github.com/rspec/rspec-collection_matchers,
  or you can rewrite your expectations with something like
  `expect(your_object.size).to eq(num)`. (Hugo Baraúna)
* Rename `be_true` and `be_false` to `be_truthy` and `be_falsey`. (Sam Phippen)
* Make `expect { }.to_not raise_error(SomeSpecificClass, message)`,
       `expect { }.to_not raise_error(SomeSpecificClass)` and
       `expect { }.to_not raise_error(message)` invalid, since they are prone
  to hiding failures. Instead, use `expect { }.to_not raise_error` (with no
  args). (Sam Phippen)
* Within `RSpec::Matchers.define` blocks, helper methods made available
  either via `def self.helper` or `extend HelperModule` are no longer
  available to the `match` block (or any of the others). Instead
  `include` your helper module and define the helper method as an
  instance method. (Myron Marston)
* Force upgrading Diff::LCS for encoding compatability with diffs. (Jon Rowe)

Enhancements:

* Support `do..end` style block with `raise_error` matcher. (Yuji Nakayama)
* Rewrote custom matcher DSL to simplify its implementation and solve a
  few issues. (Myron Marston)
* Allow early `return` from within custom matcher DSL blocks. (Myron
  Marston)
* The custom matcher DSL's `chain` can now accept a block. (Myron
  Marston)
* Support setting an expectation on a `raise_error` matcher via a chained
  `with_message` method call. (Sam Phippen)

Bug Fixes:

* Allow `include` and `match` matchers to be used from within a
  DSL-defined custom matcher's `match` block. (Myron Marston)
* Correct encoding error message on diff failure (Jon Rowe)

Deprecations:

 * Using the old `:should` syntax without explicitly configuring it is deprecated.
   It will continue to work but will emit a deprecation warning in RSpec 3 if
   you do not explicitly enable it. (Sam Phippen)

### 2.99.2 / 2014-07-21
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.99.1...v2.99.2)

Bug Fixes:

* Fix regression in `Expectations#method_handle_for` where proxy objects
  with method delegated would wrongly not return a method handle.
  (Jon Rowe, #594)
* Fix issue with detection of generic operator matchers so they work
  correctly when undefined. (Myron Marston, #597)

### 2.99.1 / 2014-06-19
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.99.0...v2.99.1)

Bug Fixes:

* Fix typo in custom matcher `expected` deprecation warning -- it's
  `expected_as_array`, not `expected_array`. (Frederick Cheung, #562)

### 2.99.0 / 2014-06-01
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.99.0.rc1...v2.99.0)

Enhancements:

* Special case deprecation message for `errors_on` with `rspec-rails` to be more useful.
  (Aaron Kromer)

### 2.99.0.rc1 / 2014-05-18
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.99.0.beta2...2.99.0.rc1)

Deprecations:

* Deprecate `matcher_execution_context` attribute on DSL-defined
  custom matchers. (Myron Marston)
* Deprecate `RSpec::Matchers::Pretty#_pretty_print`. (Myron Marston)
* Deprecate `RSpec::Matchers::Pretty#expected_to_sentence`. (Myron Marston)
* Deprecate `RSpec::Matchers::Configuration` in favor of
  `RSpec::Expectations::Configuration`. (Myron Marston)
* Deprecate `be_xyz` predicate matcher on an object that doesn't respond to
  `xyz?` or `xyzs?`. (Daniel Fone)
* Deprecate `have_xyz` matcher on an object that doesn't respond to `has_xyz?`.
  (Daniel Fone)
* Deprecate `have_xyz` matcher on an object that has a private method `has_xyz?`.
  (Jon Rowe)
* Issue a deprecation warning when a block expectation expression is
  used with a matcher that doesn't explicitly support block expectations
  via `supports_block_expectations?`. (Myron Marston)
* Deprecate `require 'rspec-expectations'`. Use
  `require 'rspec/expectations'` instead. (Myron Marston)

### 2.99.0.beta2 / 2014-02-17
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.99.0.beta1...v2.99.0.beta2)

Deprecations:

* Deprecate chaining `by`, `by_at_least`, `by_at_most` or `to` off of
  `expect { }.not_to change { }`. The docs have always said these are
  not supported for the negative form but now they explicitly raise
  errors in RSpec 3. (Myron Marston)
* Change the semantics of `expect { }.not_to change { x }.from(y)`.
  In RSpec 2.x, this expectation would only fail if `x` started with
  the value of `y` and changed. If it started with a different value
  and changed, it would pass. In RSpec 3, it will pass only if the
  value starts at `y` and it does not change. (Myron Marston)
* Deprecate `matcher == value` as an alias for `matcher.matches?(value)`,
  in favor of `matcher === value`. (Myron Marston)
* Deprecate `RSpec::Matchers::OperatorMatcher` in favor of
  `RSpec::Matchers::BuiltIn::OperatorMatcher`. (Myron Marston)
* Deprecate auto-integration with Test::Unit and minitest.
  Instead, include `RSpec::Matchers` in the appropriate test case
  base class yourself. (Myron Marston)
* Deprecate treating `#expected` on a DSL-generated custom matcher
  as an array when only 1 argument is passed to the matcher method.
  In RSpec 3 it will be the single value in order to make diffs
  work properly. (Jon Rowe)

### 2.99.0.beta1 / 2013-11-07
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.4...v2.99.0.beta1)

Deprecations

* Deprecate `have`, `have_at_least` and `have_at_most`. You can continue using those
  matchers through https://github.com/rspec/rspec-collection_matchers, or
  you can rewrite your expectations with something like
  `expect(your_object.size).to eq(num)`. (Hugo Baraúna)
* Deprecate `be_xyz` predicate matcher when `xyz?` is a private method.
  (Jon Rowe)
* Deprecate `be_true`/`be_false` in favour of `be_truthy`/`be_falsey`
  (for Ruby's conditional semantics) or `be true`/`be false`
  (for exact equality). (Sam Phippen)
* Deprecate calling helper methods from a custom matcher with the wrong
  scope. (Myron Marston)
  * `def self.foo` / `extend Helper` can be used to add macro methods
    (e.g. methods that call the custom matcher DSL methods), but should
    not be used to define helper methods called from within the DSL
    blocks.
  * `def foo` / `include Helper` is the opposite: it's for helper methods
    callable from within a DSL block, but not for defining macros.
  * RSpec 2.x allowed helper methods defined either way to be used for
    either purpose, but RSpec 3.0 will not.

### 2.14.5 / 2014-02-01
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.4...v2.14.5)

Bug fixes

* Fix wrong matcher descriptions with falsey expected value
  (yujinakayama)

### 2.14.4 / 2013-11-06
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.3...v2.14.4)

Bug fixes

* Make the `match` matcher produce a diff output. (Jon Rowe, Ben Moss)
* Choose encoding for diff's more intelligently, and when all else fails fall
  back to default internal encoding with replacing characters. (Jon Rowe)

### 2.14.3 / 2013-09-22
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.2...v2.14.3)

Bug fixes

* Fix operator matchers (`should` syntax) when `method` is redefined on target.
  (Brandon Turner)
* Fix diffing of hashes with object based keys. (Jon Rowe)
* Fix operator matchers (`should` syntax) when operator is defined via
  `method_missing` (Jon Rowe)

### 2.14.2 / 2013-08-14
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.1...v2.14.2)

Bug fixes

* Fix `be_<predicate>` matcher to not support operator chaining like the
  `be` matcher does (e.g. `be == 5`). This led to some odd behaviors
  since `be_<predicate> == anything` returned a `BeComparedTo` matcher
  and was thus always truthy. This was a consequence of the implementation
  (e.g. subclassing the basic `Be` matcher) and was not intended behavior.
  (Myron Marston).
* Fix `change` matcher to compare using `==` in addition to `===`. This
  is important for an expression like:
  `expect {}.to change { a.class }.from(ClassA).to(ClassB)` because
  `SomeClass === SomeClass` returns false. (Myron Marston)

### 2.14.1 / 2013-08-08
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.0...2.14.1)

Bug fixes

* Ensure diff output uses the same encoding as the encoding of
  the string being diff'd to prevent `Encoding::UndefinedConversionError`
  errors (Jon Rowe).

### 2.14.0 / 2013-07-06
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.14.0.rc1...v2.14.0)

Bug fixes

* Values that are not matchers use `#inspect`, rather than `#description` for
  documentation output (Andy Lindeman, Sam Phippen).
* Make `expect(a).to be_within(x).percent_of(y)` work with negative y
  (Katsuhiko Nishimra).
* Make the `be_predicate` matcher work as expected used with `expect{...}.to
  change...`  (Sam Phippen).

### 2.14.0.rc1 / 2013-05-27
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.13.0...v2.14.0.rc1)

Enhancements

* Enhance `yield_control` so that you can specify an exact or relative
  number of times: `expect { }.to yield_control.exactly(3).times`,
  `expect { }.to yield_control.at_least(2).times`, etc (Bartek
  Borkowski).
* Make the differ that is used when an expectation fails better handle arrays
  by splitting each element of the array onto its own line. (Sam Phippen)
* Accept duck-typed strings that respond to `:to_str` as expectation messages.
  (Toby Ovod-Everett)

Bug fixes

* Fix differ to not raise errors when dealing with differently-encoded
  strings (Jon Rowe).
* Fix `expect(something).to be_within(x).percent_of(y)` where x and y are both
  integers (Sam Phippen).
* Fix `have` matcher to handle the fact that on ruby 2.0,
  `Enumerator#size` may return nil (Kenta Murata).
* Fix `expect { raise s }.to raise_error(s)` where s is an error instance
  on ruby 2.0 (Sam Phippen).
* Fix `expect(object).to raise_error` passing. This now warns the user and
  fails the spec (tomykaira).

Deprecations

* Deprecate `expect { }.not_to raise_error(SpecificErrorClass)` or
  `expect { }.not_to raise_error("some specific message")`. Using
  these was prone to hiding failures as they would allow _any other
  error_ to pass. (Sam Phippen and David Chelimsky)

### 2.13.0 / 2013-02-23
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.12.1...v2.13.0)

Enhancements

* Add support for percent deltas to `be_within` matcher:
  `expect(value).to be_within(10).percent_of(expected)`
  (Myron Marston).
* Add support to `include` matcher to allow it to be given a list
  of matchers as the expecteds to match against (Luke Redpath).

Bug fixes

* Fix `change` matcher so that it dups strings in order to handle
  mutated strings (Myron Marston).
* Fix `should be =~ /some regex/` / `expect(...).to be =~ /some regex/`.
  Previously, these either failed with a confusing `undefined method
  matches?' for false:FalseClass` error or were no-ops that didn't
  actually verify anything (Myron Marston).
* Add compatibility for diff-lcs 1.2 and relax the version
  constraint (Peter Goldstein).
* Fix DSL-generated matchers to allow multiple instances of the
  same matcher in the same example to have different description
  and failure messages based on the expected value (Myron Marston).
* Prevent `undefined method #split for Array` error when dumping
  the diff of an array of multiline strings (Myron Marston).
* Don't blow up when comparing strings that are in an encoding
  that is not ASCII compatible (Myron Marston).
* Remove confusing "Check the implementation of #==" message
  printed for empty diffs (Myron Marston).

### 2.12.1 / 2012-12-15
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.12.0...v2.12.1)

Bug fixes

* Improve the failure message for an expression like
  `{}.should =~ {}`. (Myron Marston and Andy Lindeman)
* Provide a `match_regex` alias so that custom matchers
  built using the matcher DSL can use it (since `match`
  is a different method in that context).
  (Steven Harman)

### 2.12.0 / 2012-11-12
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.11.3...v2.12.0)

Enhancements

* Colorize diffs if the `--color` option is configured. (Alex Coplan)
* Include backtraces in unexpected errors handled by `raise_error`
  matcher (Myron Marston)
* Print a warning when users accidentally pass a non-string argument
  as an expectation message (Sam Phippen)
* `=~` and `match_array` matchers output a more useful error message when
  the actual value is not an array (or an object that responds to `#to_ary`)
  (Sam Phippen)

Bug fixes

* Fix `include` matcher so that `expect({}).to include(:a => nil)`
  fails as it should (Sam Phippen).
* Fix `be_an_instance_of` matcher so that `Class#to_s` is used in the
  description rather than `Class#inspect`, since some classes (like
  `ActiveRecord::Base`) define a long, verbose `#inspect`.
  (Tom Stuart)

### 2.11.3 / 2012-09-04
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.11.2...v2.11.3)

Bug fixes

* Fix (and deprecate) `expect { }.should` syntax so that it works even
  though it was never a documented or intended syntax. It worked as a
  consequence of the implementation of `expect` in RSpec 2.10 and
  earlier. (Myron Marston)
* Ensure #== is defined on built in matchers so that they can be composed.
  For example:

    expect {
      user.emailed!
    }.to change { user.last_emailed_at }.to be_within(1.second).of(Time.zone.now)

### 2.11.2 / 2012-07-25
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.11.1...v2.11.2)

Bug fixes

* Define `should` and `should_not` on `Object` rather than `BasicObject`
  on MacRuby. On MacRuby, `BasicObject` is defined but is not the root
  of the object hierarchy. (Gabriel Gilder)

### 2.11.1 / 2012-07-08
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.11.0...v2.11.1)

Bug fixes

* Constrain `actual` in `be_within` matcher to values that respond to `-` instead
  of requiring a specific type.
    * `Time`, for example, is a legit alternative.

### 2.11.0 / 2012-07-07
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.10.0...v2.11.0)

Enhancements

* Expand `expect` syntax so that it supports expections on bare values
  in addition to blocks (Myron Marston).
* Add configuration options to control available expectation syntaxes
  (Myron Marston):
  * `RSpec.configuration.expect_with(:rspec) { |c| c.syntax = :expect }`
  * `RSpec.configuration.expect_with(:rspec) { |c| c.syntax = :should }`
  * `RSpec.configuration.expect_with(:rspec) { |c| c.syntax = [:should, :expect] }`
  * `RSpec.configuration.add_should_and_should_not_to Delegator`

Bug fixes

* Allow only `Numeric` values to be the "actual" in the `be_within` matcher.
  This prevents confusing error messages. (Su Zhang @zhangsu)
* Define `should` and `should_not` on `BasicObject` rather than `Kernel`
  on 1.9. This makes `should` and `should_not` work properly with
  `BasicObject`-subclassed proxy objects like `Delegator`. (Myron
  Marston)

### 2.10.0 / 2012-05-03
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.9.1...v2.10.0)

Enhancements

* Add new `start_with` and `end_with` matchers (Jeremy Wadsack)
* Add new matchers for specifying yields (Myron Marston):
    * `expect {...}.to yield_control`
    * `expect {...}.to yield_with_args(1, 2, 3)`
    * `expect {...}.to yield_with_no_args`
    * `expect {...}.to yield_successive_args(1, 2, 3)`
* `match_unless_raises` takes multiple exception args

Bug fixes

* Fix `be_within` matcher to be inclusive of delta.
* Fix message-specific specs to pass on Rubinius (John Firebaugh)

### 2.9.1 / 2012-04-03
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.9.0...v2.9.1)

Bug fixes

* Provide a helpful message if the diff between two objects is empty.
* Fix bug diffing single strings with multiline strings.
* Fix for error with using custom matchers inside other custom matchers
  (mirasrael)
* Fix using execution context methods in nested DSL matchers (mirasrael)

### 2.9.0 / 2012-03-17
[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.8.0...v2.9.0)

Enhancements

* Move built-in matcher classes to RSpec::Matchers::BuiltIn to reduce pollution
  of RSpec::Matchers (which is included in every example).
* Autoload files with matcher classes to improve load time.

Bug fixes

* Align `respond_to?` and `method_missing` in DSL-defined matchers.
* Clear out user-defined instance variables between invocations of DSL-defined
  matchers.
* Dup the instance of a DSL generated matcher so its state is not changed by
  subsequent invocations.
* Treat expected args consistently across positive and negative expectations
  (thanks to Ralf Kistner for the heads up)

### 2.8.0 / 2012-01-04

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.8.0.rc2...v2.8.0)

Enhancements

* Better diff output for Hash (Philippe Creux)
* Eliminate Ruby warnings (Olek Janiszewski)

### 2.8.0.rc2 / 2011-12-19

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.8.0.rc1...v2.8.0.rc2)

No changes for this release. Just releasing with the other rspec gems.

### 2.8.0.rc1 / 2011-11-06

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.7.0...v2.8.0.rc1)

Enhancements

* Use classes for the built-in matchers (they're faster).
* Eliminate Ruby warnings (Matijs van Zuijlen)

### 2.7.0 / 2011-10-16

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.6.0...v2.7.0)

Enhancements

* `HaveMatcher` converts argument using `to_i` (Alex Bepple & Pat Maddox)
* Improved failure message for the `have_xxx` matcher (Myron Marston)
* `HaveMatcher` supports `count` (Matthew Bellantoni)
* Change matcher dups `Enumerable` before the action, supporting custom
  `Enumerable` types like `CollectionProxy` in Rails (David Chelimsky)

Bug fixes

* Fix typo in `have(n).xyz` documentation (Jean Boussier)
* fix `safe_sort` for ruby 1.9.2 (`Kernel` now defines `<=>` for Object) (Peter
  van Hardenberg)

### 2.6.0 / 2011-05-12

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.5.0...v2.6.0)

Enhancements

* `change` matcher accepts regexps (Robert Davis)
* better descriptions for `have_xxx` matchers (Magnus Bergmark)
* `range.should cover(*values)` (Anders Furseth)

Bug fixes

* Removed non-ascii characters that were choking rcov (Geoffrey Byers)
* change matcher dups arrays and hashes so their before/after states can be
  compared correctly.
* Fix the order of inclusion of RSpec::Matchers in Test::Unit::TestCase and
  MiniTest::Unit::TestCase to prevent a SystemStackError (Myron Marston)

### 2.5.0 / 2011-02-05

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.4.0...v2.5.0)

Enhancements

* `should exist` works with `exist?` or `exists?` (Myron Marston)
* `expect { ... }.not_to do_something` (in addition to `to_not`)

Documentation

* improved docs for raise_error matcher (James Almond)

### 2.4.0 / 2011-01-02

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.3.0...v2.4.0)

No functional changes in this release, which was made to align with the
rspec-core-2.4.0 release.

Enhancements

* improved RDoc for change matcher (Jo Liss)

### 2.3.0 / 2010-12-12

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.2.1...v2.3.0)

Enhancements

* diff strings when include matcher fails (Mike Sassak)

### 2.2.0 / 2010-11-28

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.1.0...v2.2.0)

### 2.1.0 / 2010-11-07

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.0.1...v2.1.0)

Enhancements

* `be_within(delta).of(expected)` matcher (Myron Marston)
* Lots of new Cucumber features (Myron Marston)
* Raise error if you try `should != expected` on Ruby-1.9 (Myron Marston)
* Improved failure messages from `throw_symbol` (Myron Marston)

Bug fixes

* Eliminate hard dependency on `RSpec::Core` (Myron Marston)
* `have_matcher` - use pluralize only when ActiveSupport inflections are indeed
  defined (Josep M Bach)
* throw_symbol matcher no longer swallows exceptions (Myron Marston)
* fix matcher chaining to avoid name collisions (Myron Marston)

### 2.0.0 / 2010-10-10

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.0.0.rc...v2.0.0)

Enhancements

* Add match_for_should_not method to matcher DSL (Myron Marston)

Bug fixes

* `respond_to` matcher works correctly with `should_not` with multiple methods
  (Myron Marston)
* `include` matcher works correctly with `should_not` with multiple values
  (Myron Marston)

### 2.0.0.rc / 2010-10-05

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.0.0.beta.22...v2.0.0.rc)

Enhancements

* `require 'rspec/expectations'` in a T::U or MiniUnit suite (Josep M. Bach)

Bug fixes

* change by 0 passes/fails correctly (Len Smith)
* Add description to satisfy matcher

### 2.0.0.beta.22 / 2010-09-12

[Full Changelog](http://github.com/rspec/rspec-expectations/compare/v2.0.0.beta.20...v2.0.0.beta.22)

Enhancements

* diffing improvements
    * diff multiline strings
    * don't diff single line strings
    * don't diff numbers (silly)
    * diff regexp + multiline string

Bug fixes
    * `should[_not]` change now handles boolean values correctly
