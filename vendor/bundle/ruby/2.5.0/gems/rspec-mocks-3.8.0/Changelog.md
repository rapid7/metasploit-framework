### 3.8.0 / 2018-08-04
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.7.0...v3.8.0)

Bug Fixes:

* Issue error when encountering invalid "counted" negative message expectations.
  (Sergiy Yarinovskiy, #1212)
* Ensure `allow_any_instance_of` and `expect_any_instance_of` can be temporarily
  supressed. (Jon Rowe, #1228)
* Ensure `expect_any_instance_of(double).to_not have_received(:some_method)`
  fails gracefully (as its not supported) rather than issuing a `NoMethodError`.
  (Maxim Krizhanovsky, #1231)

### 3.7.0 / 2017-10-17
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.6.0...v3.7.0)

Enhancements:

* Improve compatibility with `--enable-frozen-string-literal` option
  on Ruby 2.3+. (Pat Allan, #1165)

Bug Fixes:

* Fix `hash_including` and `hash_excluding` so that they work against
  subclasses of `Hash`. (Aaron Rosenberg, #1167)

### 3.6.0 / 2017-05-04
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.6.0.beta2...v3.6.0)

Bug Fixes:

* Fix "instance variable @color not initialized" warning when using
  rspec-mocks without rspec-core. (Myron Marston, #1142)
* Restore aliased module methods properly when stubbing on 1.8.7.
  (Samuel Giddins, #1144)
* Allow a message chain expectation to be constrained by argument(s).
  (Jon Rowe, #1156)

### 3.6.0.beta2 / 2016-12-12
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.6.0.beta1...v3.6.0.beta2)

Enhancements:

* Add new `without_partial_double_verification { }` API that lets you
  temporarily turn off partial double verification for an example.
  (Jon Rowe, #1104)

### 3.6.0.beta1 / 2016-10-09
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.5.0...v3.6.0.beta1)

Bug Fixes:

* Return the test double instance form `#freeze` (Alessandro Berardi, #1109)
* Allow the special logic for stubbing `new` to work when `<Class>.method` has
  been redefined. (Proby, #1119)

### 3.5.0 / 2016-07-01
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.5.0.beta4...v3.5.0)

Enhancements:

* Provides a nice string representation of
  `RSpec::Mocks::MessageExpectation` (Myron Marston, #1095)

### 3.5.0.beta4 / 2016-06-05
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.5.0.beta3...v3.5.0.beta4)

Enhancements:

* Add `and_throw` to any instance handling. (Tobias Bühlmann, #1068)

### 3.5.0.beta3 / 2016-04-02
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.5.0.beta2...v3.5.0.beta3)

Enhancements:

* Issue warning when attempting to use unsupported
  `allow(...).to receive(...).ordered`. (Jon Rowe, #1000)
* Add `rspec/mocks/minitest_integration`, to properly integrate rspec-mocks
  with minitest. (Myron Marston, #1065)

### 3.5.0.beta2 / 2016-03-10
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.5.0.beta1...v3.5.0.beta2)

Enhancements:

* Improve error message displayed when using `and_wrap_original` on pure test
  doubles. (betesh, #1063)

Bug Fixes:

* Fix issue that prevented `receive_message_chain(...).with(...)` working
  correctly on "any instance" mocks. (Jon Rowe, #1061)

### 3.5.0.beta1 / 2016-02-06
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.4.1...v3.5.0.beta1)

Bug Fixes:

* Allow `any_instance_of(...).to receive(...)` to use `and_yield` multiple
  times. (Kilian Cirera Sant, #1054)
* Allow matchers which inherit from `rspec-mocks` matchers to be used for
  `allow`. (Andrew Kozin, #1056)
* Prevent stubbing `respond_to?` on partial doubles from causing infinite
  recursion. (Jon Rowe, #1013)
* Prevent aliased methods from disapearing after being mocked with
  `any_instance` (regression from #1043). (Joe Rafaniello, #1060)

### 3.4.1 / 2016-01-10
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.4.0...v3.4.1)

Bug Fixes:

* Fix `any_instance` to work properly on Ruby 2.3. (Joe Rafaniello, #1043)

### 3.4.0 / 2015-11-11
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.3.2...v3.4.0)

Enhancements:

* Make `expect(...).to have_received` work without relying upon
  rspec-expectations. (Myron Marston, #978)
* Add option for failing tests when expectations are set on `nil`.
  (Liz Rush, #983)

Bug Fixes:

* Fix `have_received { ... }` so that any block passed when the message
  was received is forwarded to the `have_received` block. (Myron Marston, #1006)
* Fix infinite loop in error generator when stubbing `respond_to?`.
  (Alex Dowad, #1022)
* Fix issue with using `receive` on subclasses (at a class level) with 1.8.7.
  (Alex Dowad, #1026)

### 3.3.2 / 2015-07-15
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.3.1...v3.3.2)

Bug Fixes:

* Prevent thread deadlock errors during proxy creation (e.g. when using
  `before_verifying_doubles` callbacks). (Jon Rowe, #980, #979)

### 3.3.1 / 2015-06-19
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.3.0...v3.3.1)

Bug Fixes:

* Fix bug in `before_verifying_double` callback logic that caused it to be called
  once for each class in the ancestor list when mocking or stubbing a class. Now
  it is only called for the mocked or stubbed class, as you would expect. (Sam
  Phippen, #974)

### 3.3.0 / 2015-06-12
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.2.1...v3.3.0)

Enhancements:

* When stubbing `new` on `MyClass` or `class_double(MyClass)`, use the
  method signature from `MyClass#initialize` to verify arguments.
  (Myron Marston, #886)
* Use matcher descriptions when generating description of received arguments
  for mock expectation failures. (Tim Wade, #891)
* Avoid loading `stringio` unnecessarily. (Myron Marston, #894)
* Verifying doubles failure messages now distinguish between class and instance
  level methods. (Tim Wade, #896, #908)
* Improve mock expectation failure messages so that it combines both
  number of times and the received arguments in the output. (John Ceh, #918)
* Improve how test doubles are represented in failure messages.
  (Siva Gollapalli, Myron Marston, #932)
* Rename `RSpec::Mocks::Configuration#when_declaring_verifying_double` to
  `RSpec::Mocks::Configuration#before_verifying_doubles` and utilise when
  verifying partial doubles. (Jon Rowe, #940)
* Use rspec-support's `ObjectFormatter` for improved formatting of
  arguments in failure messages so that, for example, full time
  precisions is displayed for time objects. (Gavin Miller, Myron Marston, #955)

Bug Fixes:

* Ensure expectations that raise eagerly also raise during RSpec verification.
  This means that if exceptions are caught inside test execution the test will
  still fail. (Sam Phippen, #884)
* Fix `have_received(msg).with(args).exactly(n).times` and
  `receive(msg).with(args).exactly(n).times` failure messages
  for when the message was received the wrong number of times with
  the specified args, and also received additional times with other
  arguments. Previously it confusingly listed the arguments as being
  mis-matched (even when the double was allowed to receive with any
  args) rather than listing the count. (John Ceh, #918)
* Fix `any_args`/`anything` support so that we avoid calling `obj == anything`
  on user objects that may have improperly implemented `==` in a way that
  raises errors. (Myron Marston, #924)
* Fix edge case involving stubbing the same method on a class and a subclass
  which previously hit a `NoMethodError` internally in RSpec. (Myron Marston #954)
* Fix edge case where the message received count would be incremented multiple
  times for one failure. (Myron Marston, #957)
* Fix failure messages for when spies received the expected message with
  different arguments and also received another message. (Maurício Linhares, #960)
* Silence whitespace-only diffs. (Myron Marston, #969)

### 3.2.1 / 2015-02-23
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.2.0...v3.2.1)

Bug Fixes:

* Add missing `rspec/support/differ` require so that rspec-mocks can be
  used w/o rspec-expectations (which also loads the differ and hided the
  fact we forgot to require it). (Myron Marston, #893)
* Revert tracking of received arg mutation (added in 3.2.0 to provide an
  error in a situation we can't support) as our implementation has side
  effects on non-standard objects and there's no solution we could come
  up with that always works. (Myron Marston, #900)

### 3.2.0 / 2015-02-03
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.1.3...v3.2.0)

Enhancements:

* Treat `any_args` as an arg splat, allowing it to match an arbitrary
  number of args at any point in an arg list. (Myron Marston, #786)
* Print diffs when arguments in mock expectations are mismatched.
  (Sam Phippen, #751)
* Support names for verified doubles (`instance_double`, `instance_spy`,
  `class_double`, `class_spy`, `object_double`, `object_spy`). (Cezary
  Baginski, #826)
* Make `array_including` and `hash_including` argument matchers composable.
  (Sam Phippen, #819)
* Make `allow_any_instance_of(...).to receive(...).and_wrap_original`
  work. (Ryan Fitzgerald, #869)

Bug Fixes:

* Provide a clear error when users wrongly combine `no_args` with
  additional arguments (e.g. `expect().to receive().with(no_args, 1)`).
  (Myron Marston, #786)
* Provide a clear error when users wrongly use `any_args` multiple times in the
  same argument list (e.g. `expect().to receive().with(any_args, 1, any_args)`.
  (Myron Marston, #786)
* Prevent the error generator from using user object #description methods.
  See [#685](https://github.com/rspec/rspec-mocks/issues/685).
  (Sam Phippen, #751)
* Make verified doubles declared as `(instance|class)_double(SomeConst)`
  work properly when `SomeConst` has previously been stubbed.
  `(instance|class)_double("SomeClass")` already worked properly.
  (Myron Marston, #824)
* Add a matcher description for `receive`, `receive_messages` and
  `receive_message_chain`. (Myron Marston, #828)
* Validate invocation args for null object verified doubles.
  (Myron Marston, #829)
* Fix `RSpec::Mocks::Constant.original` when called with an invalid
  constant to return an object indicating the constant name is invalid,
  rather than blowing up. (Myron Marston, #833)
* Make `extend RSpec::Mocks::ExampleMethods` on any object work properly
  to add the rspec-mocks API to that object. Previously, `expect` would
  be undefined. (Myron Marston, #846)
* Fix `require 'rspec/mocks/standalone'` so that it only affects `main`
  and not every object. It's really only intended to be used in a REPL
  like IRB, but some gems have loaded it, thinking it needs to be loaded
  when using rspec-mocks outside the context of rspec-core.
  (Myron Marston, #846)
* Prevent message expectations from being modified by customization methods
  (e.g. `with`) after they have been invoked. (Sam Phippen and Melanie Gilman, #837)
* Handle cases where a method stub cannot be removed due to something
  external to RSpec monkeying with the method definition. This can
  happen, for example, when you `file.reopen(io)` after previously
  stubbing a method on the `file` object. (Myron Marston, #853)
* Provide a clear error when received message args are mutated before
  a `have_received(...).with(...)` expectation. (Myron Marston, #868)

### 3.1.3 / 2014-10-08
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.1.2...v3.1.3)

Bug Fixes:

* Correct received messages count when used with `have_received` matcher.
  (Jon Rowe, #793)
* Provide a clear error message when you use `allow_any_instance_of(...)` or
  `expect_any_instance_of(...)` with the `have_received` matcher (they are
  not intended to be used together and previously caused an odd internal
  failure in rspec-mocks). (Jon Rowe, #799).
* Fix verified double `with` verification so that it applies to method
  stubs. (Myron Marston, #790)

### 3.1.2 / 2014-09-26
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.1.1...v3.1.2)

Bug Fixes:

* Provide a clear error message when you use `allow(...)` with the
  `have_received` matcher (they are not intended to be used together
  and previously caused an odd internal failure in rspec-mocks). (Jon Rowe, #788).

### 3.1.1 / 2014-09-18
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.1.0...v3.1.1)

Bug Fixes:

* Prevent included modules being detected as prepended modules on Ruby 2.0
  when using `any_instance_of(...)`. (Tony Novak, #781)

### 3.1.0 / 2014-09-04
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.4...v3.1.0)

Enhancements:

* Add spying methods (`spy`, `ìnstance_spy`, `class_spy` and `object_spy`)
  which create doubles as null objects for use with spying in testing. (Sam
  Phippen, #671)
* `have_received` matcher will raise "does not implement" errors correctly when
  used with verifying doubles and partial doubles. (Xavier Shay, #722)
* Allow matchers to be used in place of keyword arguments in `with`
  expectations. (Xavier Shay, #726)
* Add `thrice` modifier to message expectation interface as a synonym
  for `exactly(3).times`. (Dennis Taylor, #753)
* Add more `thrice` synonyms e.g. `.at_least(:thrice)`, `.at_most(:thrice)`,
  `receive(...).thrice` and `have_received(...).thrice`. (Jon Rowe, #754)
* Add `and_wrap_original` modifier for partial doubles to mutate the
  response from a method. (Jon Rowe, #762)

Bug Fixes:

* Remove `any_number_of_times` from `any_instance` recorders that were
  erroneously causing mention of the method in documentation. (Jon Rowe, #760)
* Prevent included modules being detected as prepended modules on Ruby 2.0.
  (Eugene Kenny, #771)

### 3.0.4 / 2014-08-14
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.3...v3.0.4)

Bug Fixes:

* Restore `kind_of(x)` to match using `arg.kind_of?(x)` (like RSpec 2)
  rather than `x === arg`. (Jon Rowe, #750)

### 3.0.3 / 2014-07-21
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.2...v3.0.3)

Bug Fixes:

* `have_received` matcher will raise "does not implement" errors correctly when
  used with verifying doubles and partial doubles. (Xavier Shay, #722)
* Make `double.as_null_object.dup` and `double.as_null_object.clone`
  make the copies be null objects. (Myron Marston, #732)
* Don't inadvertently define `BasicObject` in 1.8.7. (Chris Griego, #739)

### 3.0.2 / 2014-06-19
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.1...v3.0.2)

Bug Fixes:

* Fix edge case that triggered "can't add a new key into hash during
  iteration" during mock verification. (Sam Phippen, Myron Marston, #711)
* Fix verifying doubles so that when they accidentally leak into another
  example, they provide the same clear error message that normal doubles
  do. (Myron Marston, #718)
* Make `ordered` work with exact receive counts. (Sam Phippen, #713)

### 3.0.1 / 2014-06-07
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.0...v3.0.1)

Bug Fixes:

* Fix `receive_message_chain(...)` so that it supports `with` just like
  `stub_chain` did. (Jon Rowe, #697)
* Fix regression in `expect_any_instance_of` so that it expects the
  message on _any_ instance rather than on _every_ instance.
  (Myron Marston, #699)

### 3.0.0 / 2014-06-01
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.0.rc1...v3.0.0)

Bug Fixes:

* Fix module prepend detection to work properly on ruby 2.0 for a case
  where a module is extended onto itself. (Myron Marston)
* Fix `transfer_nested_constants` option so that transferred constants
  get properly reset at the end of the example. (Myron Marston)
* Fix `config.transfer_nested_constants = true` so that you don't
  erroneously get errors when stubbing a constant that is not a module
  or a class. (Myron Marston)
* Fix regression that caused `double(:class => SomeClass)` to later
  trigger infinite recursion. (Myron Marston)
* Fix bug in `have_received(...).with(...).ordered` where it was not
  taking the args into account when checking the order. (Myron Marston)
* Fix bug in `have_received(...).ordered` where it was wrongly
  considering stubs when checking the order. (Myron Marston)
* Message expectation matchers now show descriptions from argument
  matchers when their expectations aren't met. (Jon Rowe)
* Display warning when encountering `TypeError` during instance method
  staging on 2.0.0-p195, suffers from https://bugs.ruby-lang.org/issues/8686
  too. (Cezar Halmagean).

### 3.0.0.rc1 / 2014-05-18
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.0.beta2...v3.0.0.rc1)

Breaking Changes for 3.0.0:

* Remove `RSpec::Mocks::TestDouble.extend_onto`. (Myron Marston)
* Remove `RSpec::Mocks::ConstantStubber`. (Jon Rowe)
* Make monkey-patch of Marshal to support dumping of stubbed objects opt-in.
  (Xavier Shay)

Enhancements:

* Instead of crashing when cleaning up stub methods on a frozen object, it now
  issues a warning explaining that it's impossible to clean up the stubs.
  (Justin Coyne and Sam Phippen)
* Add meaningful descriptions to `anything`, `duck_type` and `instance_of` argument
  matchers. (Jon Rowe)

Bug Fixes:

* Fix regression introduced in 3.0.0.beta2 that caused
  `double.as_null_object.to_str` to return the double rather
  than a string. (Myron Marston)
* Fix bug in `expect(dbl).to receive_message_chain(:foo, :bar)` where it was
  not setting an expectation for the last message in the chain.
  (Jonathan del Strother)
* Allow verifying partial doubles to have private methods stubbed. (Xavier Shay)
* Fix bug with allowing/expecting messages on Class objects which have had
  their singleton class prepended to. (Jon Rowe)
* Fix an issue with 1.8.7 not running implementation blocks on partial doubles.
  (Maurício Linhares)
* Prevent `StackLevelTooDeep` errors when stubbing an `any_instance` method that's
  accessed in `inspect` by providing our own inspect output. (Jon Rowe)
* Fix bug in `any_instance` logic that did not allow you to mock or stub
  private methods if `verify_partial_doubles` was configured. (Oren Dobzinski)
* Include useful error message when trying to observe an unimplemented method
  on an any instance. (Xavier Shay)
* Fix `and_call_original` to work properly when multiple classes in an
  inheritance hierarchy have been stubbed with the same method. (Myron Marston)
* Fix `any_instance` so that it updates existing instances that have
  already been stubbed. (Myron Marston)
* Fix verified doubles so that their class name is included in failure
  messages. (Myron Marston)
* Fix `expect_any_instance_of` so that when the message is received
  on an individual instance that has been directly stubbed, it still
  satisfies the expectation. (Sam Phippen, Myron Marston)
* Explicitly disallow using `any_instance` to mock or stub a method
  that is defined on a module prepended onto the class. This triggered
  `SystemStackError` before and is very hard to support so we are not
  supporting it at this time. (Myron Marston)

### 3.0.0.beta2 / 2014-02-17
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v3.0.0.beta1...v3.0.0.beta2)

Breaking Changes for 3.0.0:

* Rename `RSpec::Mocks::Mock` to `RSpec::Mocks::Double`. (Myron Marston)
* Change how to integrate rspec-mocks in other test frameworks. You now
  need to include `RSpec::Mocks::ExampleMethods` in your test context.
  (Myron Marston)
* Prevent RSpec mocks' doubles and partial doubles from being used outside of
  the per-test lifecycle (e.g. from a `before(:all)` hook). (Sam Phippen)
* Remove the `host` argument of `RSpec::Mocks.setup`. Instead
  `RSpec::Mocks::ExampleMethods` should be included directly in the scope where
  RSpec's mocking capabilities are used. (Sam Phippen)
* Make test doubles raise errors if you attempt to use them after they
  get reset, to help surface issues when you accidentally retain
  references to test doubles and attempt to reuse them in another
  example. (Myron Marston)
* Remove support for `and_return { value }` and `and_return` without arguments. (Yuji Nakayama)

Enhancements:

* Add `receive_message_chain` which provides the functionality of the old
  `stub_chain` for the new allow/expect syntax. Use it like so: `allow(...).to
  receive_message_chain(:foo, :bar, :bazz)`. (Sam Phippen).
* Change argument matchers to use `===` as their primary matching
  protocol, since their semantics mirror that of a case or rescue statement
  (which uses `===` for matching). (Myron Marston)
* Add `RSpec::Mocks.with_temporary_scope`, which allows you to create
  temporary rspec-mocks scopes in arbitrary places (such as a
  `before(:all)` hook). (Myron Marston)
* Support keyword arguments when checking arity with verifying doubles.
  (Xavier Shay)

Bug Fixes:

* Fix regression in 3.0.0.beta1 that caused `double("string_name" => :value)`
  to stop working. (Xavier Shay)
* Fix the way rspec-mocks and rspec-core interact so that if users
  define a `let` with the same name as one of the methods
  from `RSpec::Mocks::ArgumentMatchers`, the user's `let` takes
  precedence. (Michi Huber, Myron Marston)
* Fix verified doubles so that their methods match the visibility
  (public, protected or private) of the interface they verify
  against. (Myron Marston)
* Fix verified null object doubles so that they do not wrongly
  report that they respond to anything. They only respond to methods
  available on the interface they verify against. (Myron Marston)
* Fix deprecation warning for use of old `:should` syntax w/o explicit
  config so that it no longer is silenced by an extension gem such
  as rspec-rails when it calls `config.add_stub_and_should_receive_to`.
  (Sam Phippen)
* Fix `expect` syntax so that it does not wrongly emit a "You're
  overriding a previous implementation for this stub" warning when
  you are not actually doing that. (Myron Marston)
* Fix `any_instance.unstub` when used on sub classes for whom the super
  class has had `any_instance.stub` invoked on. (Jon Rowe)
* Fix regression in `stub_chain`/`receive_message_chain` that caused
  it to raise an `ArgumentError` when passing args to the stubbed
  methods. (Sam Phippen)
* Correct stub of undefined parent modules all the way down when stubbing a
  nested constant. (Xavier Shay)
* Raise `VerifyingDoubleNotDefinedError` when a constant is not defined for
  a verifying class double. (Maurício Linhares)
* Remove `Double#to_str`, which caused confusing `raise some_double`
  behavior. (Maurício Linhares)

### 3.0.0.beta1 / 2013-11-07
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.4...v3.0.0.beta1)

Breaking Changes for 3.0.0:

* Raise an explicit error if `should_not_receive(...).and_return` is used. (Sam
  Phippen)
* Remove 1.8.6 workarounds. (Jon Rowe)
* Remove `stub!` and `unstub!`. (Sam Phippen)
* Remove `mock(name, methods)` and `stub(name, methods)`, leaving
  `double(name, methods)` for creating test doubles. (Sam Phippen, Michi Huber)
* Remove `any_number_of_times` since `should_receive(:msg).any_number_of_times`
  is really a stub in a mock's clothing. (Sam Phippen)
* Remove support for re-using the same null-object test double in multiple
  examples.  Test doubles are designed to only live for one example.
  (Myron Marston)
* Make `at_least(0)` raise an error. (Sam Phippen)
* Remove support for `require 'spec/mocks'` which had been kept
  in place for backwards compatibility with RSpec 1. (Myron Marston)
* Blocks provided to `with` are always used as implementation. (Xavier Shay)
* The config option (added in 2.99) to yield the receiver to
  `any_instance` implementation blocks now defaults to "on". (Sam Phippen)

Enhancements:

* Allow the `have_received` matcher to use a block to set further expectations
  on arguments. (Tim Cowlishaw)
* Provide `instance_double` and `class_double` to create verifying doubles,
  ported from `rspec-fire`. (Xavier Shay)
* `as_null_object` on a verifying double only responds to defined methods.
  (Xavier Shay)
* Provide `object_double` to create verified doubles of specific object
  instances. (Xavier Shay)
* Provide `verify_partial_doubles` configuration that provides `object_double`
  like verification behaviour on partial doubles. (Xavier Shay)
* Improved performance of double creation, particularly those with many
  attributes. (Xavier Shay)
* Default value of `transfer_nested_constants` option for constant stubbing can
  be configured. (Xavier Shay)
* Messages can be allowed or expected on in bulk via
  `receive_messages(:message => :value)`. (Jon Rowe)
* `allow(Klass.any_instance)` and `expect(Klass.any_instance)` now print a
  warning. This is usually a mistake, and users usually want
  `allow_any_instance_of` or `expect_any_instance_of` instead. (Sam Phippen)
* `instance_double` and `class_double` raise `ArgumentError` if the underlying
  module is loaded and the arity of the method being invoked does not match the
  arity of the method as it is actually implemented. (Andy Lindeman)
* Spies can now check their invocation ordering is correct. (Jon Rowe)

Deprecations:

* Using the old `:should` syntax without explicitly configuring it
  is deprecated. It will continue to work but will emit a deprecation
  warning in RSpec 3 if you do not explicitly enable it. (Sam Phippen)

Bug Fixes:

* Fix `and_call_original` to handle a complex edge case involving
  singleton class ancestors. (Marc-André Lafortune, Myron Marston)
* When generating an error message for unexpected arguments,
  use `#inspect` rather than `#description` if `#description`
  returns `nil` or `''` so that you still get a useful message.
  (Nick DeLuca)

### 2.99.4 / 2015-06-19
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.3...v2.99.4)

Bug Fixes:

* Add missing deprecation for using `with` with no arguments e.g. `with()`. (Yousuke, #970)

### 2.99.3 / 2015-01-09
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.2...v2.99.3)

Bug Fixes:

* Fix regression that caused an error when a test double was deserialized from YAML. (Yuji Nakayama, #777)

### 2.99.2 / 2014-07-21
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.1...v2.99.2)

Enhancements:

* Warn about upcoming change to `#===` matching and `DateTime#===` behaviour.
  (Jon Rowe, #735)

### 2.99.1 / 2014-06-12
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.0...v2.99.1)

Bug Fixes:

* Fix bug that caused errors at the end of each example
  when a `double.as_null_object` had been frozen. (Yuji Nakayama, #698)

Deprecations:

* Deprecate freezing a test double. (Yuji Nakayama, #698)

### 2.99.0 / 2014-06-01
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.0.rc1...v2.99.0)

No changes. Just taking it out of pre-release.

### 2.99.0.rc1 / 2014-05-18
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.0.beta2...v2.99.0.rc1)

Deprecations:

* Deprecate `RSpec::Mocks::TestDouble.extend_onto`. (Myron Marston)
* Deprecate `RSpec::Mocks::ConstantStubber`. (Jon Rowe)
* Deprecate `Marshal.dump` monkey-patch without opt-in. (Xavier Shay)

### 2.99.0.beta2 / 2014-02-17
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.99.0.beta1...v2.99.0.beta2)

Deprecations:

* Deprecate `RSpec::Mocks::Mock` in favor of `RSpec::Mocks::Double`.
  (Myron Marston)
* Deprecate the `host` argument of `RSpec::Mocks.setup`. Instead
  `RSpec::Mocks::ExampleMethods` should be included directly in the scope where
  RSpec's mocking capabilities are used. (Sam Phippen)
* Deprecate using any of rspec-mocks' features outside the per-test
  lifecycle (e.g. from a `before(:all)` hook). (Myron Marston)
* Deprecate re-using a test double in another example. (Myron Marston)
* Deprecate `and_return { value }` and `and_return` without arguments. (Yuji Nakayama)

### 2.99.0.beta1 / 2013-11-07
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.4...v2.99.0.beta1)

Deprecations

* Expecting to use lambdas or other strong arity implementations for stub
  methods with mis-matched arity is deprecated and support for them will be
  removed in 3.0. Either provide the right amount of arguments or use a weak
  arity implementation (methods with splats or procs). (Jon Rowe)
* Using the same test double instance in multiple examples is deprecated. Test
  doubles are only meant to live for one example. The mocks and stubs have
  always been reset between examples; however, in 2.x the `as_null_object`
  state was not reset and some users relied on this to have a null object
  double that is used for many examples. This behavior will be removed in 3.0.
  (Myron Marston)
* Print a detailed warning when an `any_instance` implementation block is used
  when the new `yield_receiver_to_any_instance_implementation_blocks` config
  option is not explicitly set, as RSpec 3.0 will default to enabling this new
  feature. (Sam Phippen)

Enhancements:

* Add a config option to yield the receiver to `any_instance` implementation
  blocks. (Sam Phippen)

### 2.14.6 / 2014-02-20
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.5...v2.14.6)

Bug Fixes:

* Ensure `any_instance` method stubs and expectations are torn down regardless of
  expectation failures. (Sam Phippen)

### 2.14.5 / 2014-02-01
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.4...v2.14.5)

Bug Fixes:

* Fix regression that caused block implementations to not receive all
  args on 1.8.7 if the block also receives a block, due to Proc#arity
  reporting `1` no matter how many args the block receives if it
  receives a block, too. (Myron Marston)

### 2.14.4 / 2013-10-15
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.3...v2.14.4)

Bug Fixes:

* Fix issue where unstubing methods on "any instances" would not
  remove stubs on existing instances (Jon Rowe)
* Fix issue with receive(:message) do ... end precedence preventing
  the usage of modifications (`and_return` etc) (Jon Rowe)

### 2.14.3 / 2013-08-08
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.2...v2.14.3)

Bug Fixes:

* Fix stubbing some instance methods for classes whose hierarchy includes
  a prepended Module (Bradley Schaefer)

### 2.14.2 / 2013-07-30
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.1...v2.14.2)

Bug Fixes:

* Fix `as_null_object` doubles so that they return `nil` from `to_ary`
  (Jon Rowe).
* Fix regression in 2.14 that made `stub!` (with an implicit receiver)
  return a test double rather than stub a method (Myron Marston).

### 2.14.1 / 2013-07-07
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.0...v2.14.1)

Bug Fixes:

* Restore `double.as_null_object` behavior from 2.13 and earlier: a
  double's nullness persisted between examples in earlier examples.
  While this is not an intended use case (test doubles are meant to live
  for only one example), we don't want to break behavior users rely
  on in a minor relase.  This will be deprecated in 2.99 and removed
  in 3.0. (Myron Marston)

### 2.14.0 / 2013-07-06
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.14.0.rc1...v2.14.0)

Enhancements:

* Document test spies in the readme. (Adarsh Pandit)
* Add an `array_including` matcher. (Sam Phippen)
* Add a syntax-agnostic API for mocking or stubbing a method. This is
  intended for use by libraries such as rspec-rails that need to mock
  or stub a method, and work regardless of the syntax the user has
  configured (Paul Annesley, Myron Marston and Sam Phippen).

Bug Fixes:

* Fix `double` so that it sets up passed stubs correctly regardless of
  the configured syntax (Paul Annesley).
* Allow a block implementation to be used in combination with
  `and_yield`, `and_raise`, `and_return` or `and_throw`. This got fixed
  in 2.13.1 but failed to get merged into master for the 2.14.0.rc1
  release (Myron Marston).
* `Marshal.dump` does not unnecessarily duplicate objects when rspec-mocks has
  not been fully initialized. This could cause errors when using `spork` or
  similar preloading gems (Andy Lindeman).

### 2.14.0.rc1 / 2013-05-27
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.13.0...v2.14.0.rc1)

Enhancements:

* Refactor internals so that the mock proxy methods and state are held
  outside of the mocked object rather than inside it. This paves the way
  for future syntax enhancements and removes the need for some hacky
  work arounds for `any_instance` dup'ing and `YAML` serialization,
  among other things. Note that the code now relies upon `__id__`
  returning a unique, consistent value for any object you want to
  mock or stub (Myron Marston).
* Add support for test spies. This allows you to verify a message
  was received afterwards using the `have_received` matcher.
  Note that you must first stub the method or use a null double.
  (Joe Ferris and Joël Quenneville)
* Make `at_least` and `at_most` style receive expectations print that they were
  expecting at least or at most some number of calls, rather than just the
  number of calls given in the expectation (Sam Phippen)
* Make `with` style receive expectations print the args they were expecting, and
  the args that they got (Sam Phippen)
* Fix some warnings seen under ruby 2.0.0p0 (Sam Phippen).
* Add a new `:expect` syntax for message expectations
  (Myron Marston and Sam Phippen).

Bug fixes

* Fix `any_instance` so that a frozen object can be `dup`'d when methods
  have been stubbed on that type using `any_instance` (Jon Rowe).
* Fix `and_call_original` so that it properly raises an `ArgumentError`
  when the wrong number of args are passed (Jon Rowe).
* Fix `double` on 1.9.2 so you can wrap them in an Array
  using `Array(my_double)` (Jon Rowe).
* Fix `stub_const` and `hide_const` to handle constants that redefine `send`
  (Sam Phippen).
* Fix `Marshal.dump` extension so that it correctly handles nil.
  (Luke Imhoff, Jon Rowe)
* Fix isolation of `allow_message_expectations_on_nil` (Jon Rowe)
* Use inspect to format actual arguments on expectations in failure messages (#280, Ben Langfeld)
* Protect against improperly initialised test doubles (#293) (Joseph Shraibman and Jon Rowe)

Deprecations

* Deprecate `stub` and `mock` as aliases for `double`. `double` is the
  best term for creating a test double, and it reduces confusion to
  have only one term (Michi Huber).
* Deprecate `stub!` and `unstub!` in favor of `stub` and `unstub`
  (Jon Rowe).
* Deprecate `at_least(0).times` and `any_number_of_times` (Michi Huber).

### 2.13.1 / 2013-04-06
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.13.0...v2.13.1)

Bug fixes

* Allow a block implementation to be used in combination with
  `and_yield`, `and_raise`, `and_return` or `and_throw` (Myron Marston).

### 2.13.0 / 2013-02-23
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.12.2...v2.13.0)

Bug fixes

* Fix bug that caused weird behavior when a method that had
  previously been stubbed with multiple return values (e.g.
  `obj.stub(:foo).and_return(1, 2)`) was later mocked with a
  single return value (e.g. `obj.should_receive(:foo).once.and_return(1)`).
  (Myron Marston)
* Fix bug related to a mock expectation for a method that already had
  multiple stubs with different `with` constraints. Previously, the
  first stub was used, even though it may not have matched the passed
  args. The fix defers this decision until the message is received so
  that the proper stub response can be chosen based on the passed
  arguments (Myron Marston).
* Do not call `nil?` extra times on a mocked object, in case `nil?`
  itself is expected a set number of times (Myron Marston).
* Fix `missing_default_stub_error` message so array args are handled
  properly (Myron Marston).
* Explicitly disallow `any_instance.unstub!` (Ryan Jones).
* Fix `any_instance` stubbing so that it works with `Delegator`
  subclasses (Myron Marston).
* Fix `and_call_original` so that it works with `Delegator` subclasses
  (Myron Marston).
* Fix `any_instance.should_not_receive` when `any_instance.should_receive`
  is used on the same class in the same example. Previously it would
  wrongly report a failure even when the message was not received
  (Myron Marston).

### 2.12.2 / 2013-01-27
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.12.1...v.2.12.2)

Bug fixes

* Fix `and_call_original` to work properly for methods defined
  on a module extended onto an object instance (Myron Marston).
* Fix `stub_const` with an undefined constnat name to work properly
  with constant strings that are prefixed with `::` -- and edge case
  I missed in the bug fix in the 2.12.1 release (Myron Marston).
* Ensure method visibility on a partial mock is restored after reseting
  method stubs, even on a singleton module (created via `extend self`)
  when the method visibility differs between the instance and singleton
  versions (Andy Lindeman).

### 2.12.1 / 2012-12-21
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.12.0...v2.12.1)

Bug fixes

* Fix `any_instance` to support `and_call_original`.
  (Myron Marston)
* Properly restore stubbed aliased methods on rubies
  that report the incorrect owner (Myron Marston and Andy Lindeman).
* Fix `hide_const` and `stub_const` with a defined constnat name to
  work properly with constant strings that are prefixed with `::` (Myron Marston).

### 2.12.0 / 2012-11-12
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.11.3...v2.12.0)

Enhancements

* `and_raise` can accept an exception class and message, more closely
  matching `Kernel#raise` (e.g., `foo.stub(:bar).and_raise(RuntimeError, "message")`)
  (Bas Vodde)
* Add `and_call_original`, which will delegate the message to the
  original method (Myron Marston).

Deprecations:

* Add deprecation warning when using `and_return` with `should_not_receive`
  (Neha Kumari)

### 2.11.3 / 2012-09-19
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.11.2...v2.11.3)

Bug fixes

* Fix `:transfer_nested_constants` option of `stub_const` so that it
  doesn't blow up when there are inherited constants. (Myron Marston)
* `any_instance` stubs can be used on classes that override `Object#method`.
  (Andy Lindeman)
* Methods stubbed with `any_instance` are unstubbed after the test finishes.
  (Andy Lindeman)
* Fix confusing error message when calling a mocked class method an
  extra time with the wrong arguments (Myron Marston).

### 2.11.2 / 2012-08-11
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.11.1...v2.11.2)

Bug fixes

* Don't modify `dup` on classes that don't support `dup` (David Chelimsky)
* Fix `any_instance` so that it works properly with methods defined on
  a superclass. (Daniel Eguzkiza)
* Fix `stub_const` so that it works properly for nested constants that
  share a name with a top-level constant (e.g. "MyGem::Hash"). (Myron
  Marston)

### 2.11.1 / 2012-07-09
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.11.0...v2.11.1)

Bug fixes

* Fix `should_receive` so that when it is called on an `as_null_object`
  double with no implementation, and there is a previous explicit stub
  for the same method, the explicit stub remains (rather than being
  overridden with the null object implementation--`return self`). (Myron
  Marston)

### 2.11.0 / 2012-07-07
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.10.1...v2.11.0)

Enhancements

* Expose ArgumentListMatcher as a formal API
    * supports use by 3rd party mock frameworks like Surrogate
* Add `stub_const` API to stub constants for the duration of an
  example (Myron Marston).

Bug fixes

* Fix regression of edge case behavior. `double.should_receive(:foo) { a }`
  was causing a NoMethodError when `double.stub(:foo).and_return(a, b)`
  had been setup before (Myron Marston).
* Infinite loop generated by using `any_instance` and `dup`. (Sidu Ponnappa @kaiwren)
* `double.should_receive(:foo).at_least(:once).and_return(a)` always returns a
  even if `:foo` is already stubbed.
* Prevent infinite loop when interpolating a null double into a string
  as an integer (`"%i" % double.as_null_object`). (Myron Marston)
* Fix `should_receive` so that null object behavior (e.g. returning
  self) is preserved if no implementation is given (Myron Marston).
* Fix `and_raise` so that it raises `RuntimeError` rather than
  `Exception` by default, just like ruby does. (Andrew Marshall)

### 2.10.1 / 2012-05-05
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.10.0...v2.10.1)

Bug fixes

* fix regression of edge case behavior
  (https://github.com/rspec/rspec-mocks/issues/132)
    * fixed failure of `object.should_receive(:message).at_least(0).times.and_return value`
    * fixed failure of `object.should_not_receive(:message).and_return value`

### 2.10.0 / 2012-05-03
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.9.0...v2.10.0)

Bug fixes

* fail fast when an `exactly` or `at_most` expectation is exceeded

### 2.9.0 / 2012-03-17
[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.8.0...v2.9.0)

Enhancements

* Support order constraints across objects (preethiramdev)

Bug fixes

* Allow a `as_null_object` to be passed to `with`
* Pass proc to block passed to stub (Aubrey Rhodes)
* Initialize child message expectation args to match any args (#109 -
  preethiramdev)

### 2.8.0 / 2012-01-04

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.8.0.rc2...v2.8.0)

No changes for this release. Just releasing with the other rspec gems.

### 2.8.0.rc2 / 2011-12-19

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.8.0.rc1...v2.8.0.rc2)

No changes for this release. Just releasing with the other rspec gems.

### 2.8.0.rc1 / 2011-11-06

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.7.0...v2.8.0.rc1)

Enhancements

* Eliminate Ruby warnings (Matijs van Zuijlen)

### 2.7.0 / 2011-10-16

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.6.0...v2.7.0)

Enhancements

* Use `__send__` rather than `send` (alextk)
* Add support for `any_instance.stub_chain` (Sidu Ponnappa)
* Add support for `any_instance` argument matching based on `with` (Sidu
  Ponnappa and Andy Lindeman)

Changes

* Check for `failure_message_for_should` or `failure_message` instead of
  `description` to detect a matcher (Tibor Claassen)

Bug fixes

* pass a hash to `any_instance.stub`. (Justin Ko)
* allow `to_ary` to be called without raising `NoMethodError` (Mikhail
  Dieterle)
* `any_instance` properly restores private methods (Sidu Ponnappa)

### 2.6.0 / 2011-05-12

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.5.0...v2.6.0)

Enhancements

* Add support for `any_instance.stub` and `any_instance.should_receive` (Sidu
  Ponnappa and Andy Lindeman)

Bug fixes

* fix bug in which multiple chains with shared messages ending in hashes failed
  to return the correct value

### 2.5.0 / 2011-02-05

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.4.0...v2.5.0)

Bug fixes

* message expectation counts now work in combination with a stub (Damian
  Nurzynski)
* fix failure message when message received with incorrect args (Josep M.
  Bach)

### 2.4.0 / 2011-01-02

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.3.0...v2.4.0)

No functional changes in this release, which was made to align with the
rspec-core-2.4.0 release.

### 2.3.0 / 2010-12-12

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.2.0...v2.3.0)

Bug fixes

* Fix our Marshal extension so that it does not interfere with objects that
  have their own `@mock_proxy` instance variable. (Myron Marston)

### 2.2.0 / 2010-11-28

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.1.0...v2.2.0)

Enhancements

* Added "rspec/mocks/standalone" for exploring the rspec-mocks in irb.

Bug fix

* Eliminate warning on splat args without parens (Gioele Barabucci)
* Fix bug where `obj.should_receive(:foo).with(stub.as_null_object)` would pass
  with a false positive.

### 2.1.0 / 2010-11-07

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.0.1...v2.1.0)

Bug fixes

* Fix serialization of stubbed object (Josep M Bach)

### 2.0.0 / 2010-10-10

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.0.0.beta.22...v2.0.0)

### 2.0.0.rc / 2010-10-05

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.0.0.beta.22...v2.0.0.rc)

Enhancements

* support passing a block to an expectation block (Nicolas Braem)
    * `obj.should_receive(:msg) {|&block| ... }`

Bug fixes

* Fix YAML serialization of stub (Myron Marston)
* Fix rdoc rake task (Hans de Graaff)

### 2.0.0.beta.22 / 2010-09-12

[Full Changelog](http://github.com/rspec/rspec-mocks/compare/v2.0.0.beta.20...v2.0.0.beta.22)

Bug fixes

* fixed regression that broke `obj.stub_chain(:a, :b => :c)`
* fixed regression that broke `obj.stub_chain(:a, :b) { :c }`
* `respond_to?` always returns true when using `as_null_object`
