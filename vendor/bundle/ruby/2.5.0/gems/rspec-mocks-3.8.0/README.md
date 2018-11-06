# RSpec Mocks [![Build Status](https://secure.travis-ci.org/rspec/rspec-mocks.svg?branch=master)](http://travis-ci.org/rspec/rspec-mocks) [![Code Climate](https://codeclimate.com/github/rspec/rspec-mocks.svg)](https://codeclimate.com/github/rspec/rspec-mocks)
rspec-mocks is a test-double framework for rspec with support for method stubs,
fakes, and message expectations on generated test-doubles and real objects
alike.

## Install

    gem install rspec       # for rspec-core, rspec-expectations, rspec-mocks
    gem install rspec-mocks # for rspec-mocks only

Want to run against the `master` branch? You'll need to include the dependent
RSpec repos as well. Add the following to your `Gemfile`:

```ruby
%w[rspec-core rspec-expectations rspec-mocks rspec-support].each do |lib|
  gem lib, :git => "https://github.com/rspec/#{lib}.git", :branch => 'master'
end
```
## Contributing

Once you've set up the environment, you'll need to cd into the working
directory of whichever repo you want to work in. From there you can run the
specs and cucumber features, and make patches.

NOTE: You do not need to use rspec-dev to work on a specific RSpec repo. You
can treat each RSpec repo as an independent project.

For information about contributing to RSpec, please refer to the following markdown files:
* [Build details](BUILD_DETAIL.md)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Detailed contributing guide](CONTRIBUTING.md)
* [Development setup guide](DEVELOPMENT.md)

## Test Doubles

A test double is an object that stands in for another object in your system
during a code example. Use the `double` method, passing in an optional identifier, to create one:

```ruby
book = double("book")
```

Most of the time you will want some confidence that your doubles resemble an
existing object in your system. Verifying doubles are provided for this
purpose. If the existing object is available, they will prevent you from adding
stubs and expectations for methods that do not exist or that have an invalid
number of parameters.

```ruby
book = instance_double("Book", :pages => 250)
```

Verifying doubles have some clever tricks to enable you to both test in
isolation without your dependencies loaded while still being able to validate
them against real objects. More detail is available in [their
documentation](https://github.com/rspec/rspec-mocks/blob/master/features/verifying_doubles).

Verifying doubles can also accept custom identifiers, just like double(), e.g.:

```ruby
books = []
books << instance_double("Book", :rspec_book, :pages => 250)
books << instance_double("Book", "(Untitled)", :pages => 5000)

puts books.inspect # with names, it's clearer which were actually added
```

## Method Stubs

A method stub is an implementation that returns a pre-determined value.  Method
stubs can be declared on test doubles or real objects using the same syntax.
rspec-mocks supports 3 forms for declaring method stubs:

```ruby
allow(book).to receive(:title) { "The RSpec Book" }
allow(book).to receive(:title).and_return("The RSpec Book")
allow(book).to receive_messages(
    :title => "The RSpec Book",
    :subtitle => "Behaviour-Driven Development with RSpec, Cucumber, and Friends")
```

You can also use this shortcut, which creates a test double and declares a
method stub in one statement:

```ruby
book = double("book", :title => "The RSpec Book")
```

The first argument is a name, which is used for documentation and appears in
failure messages. If you don't care about the name, you can leave it out,
making the combined instantiation/stub declaration very terse:

```ruby
double(:foo => 'bar')
```

This is particularly nice when providing a list of test doubles to a method
that iterates through them:

```ruby
order.calculate_total_price(double(:price => 1.99), double(:price => 2.99))
```

### Stubbing a chain of methods

You can use `receive_message_chain` in place of `receive` to stub a chain of messages:

```ruby
allow(double).to receive_message_chain("foo.bar") { :baz }
allow(double).to receive_message_chain(:foo, :bar => :baz)
allow(double).to receive_message_chain(:foo, :bar) { :baz }

# Given any of the above forms:
double.foo.bar # => :baz
```

Chains can be arbitrarily long, which makes it quite painless to violate the Law of Demeter in violent ways, so you should consider any use of `receive_message_chain` a code smell. Even though not all code smells indicate real problems (think fluent interfaces), `receive_message_chain` still results in brittle examples. For example, if you write `allow(foo).to receive_message_chain(:bar, :baz => 37)` in a spec and then the implementation calls `foo.baz.bar`, the stub will not work.

## Consecutive return values

When a stub might be invoked more than once, you can provide additional
arguments to `and_return`.  The invocations cycle through the list. The last
value is returned for any subsequent invocations:

```ruby
allow(die).to receive(:roll).and_return(1, 2, 3)
die.roll # => 1
die.roll # => 2
die.roll # => 3
die.roll # => 3
die.roll # => 3
```

To return an array in a single invocation, declare an array:

```ruby
allow(team).to receive(:players).and_return([double(:name => "David")])
```

## Message Expectations

A message expectation is an expectation that the test double will receive a
message some time before the example ends. If the message is received, the
expectation is satisfied. If not, the example fails.

```ruby
validator = double("validator")
expect(validator).to receive(:validate) { "02134" }
zipcode = Zipcode.new("02134", validator)
zipcode.valid?
```

## Test Spies

Verifies the given object received the expected message during the course of
the test. For a message to be verified, the given object must be setup to spy
on it, either by having it explicitly stubbed or by being a null object double
(e.g. `double(...).as_null_object`). Convenience methods are provided to easily
create null object doubles for this purpose:

```ruby
spy("invitation") # => same as `double("invitation").as_null_object`
instance_spy("Invitation") # => same as `instance_double("Invitation").as_null_object`
class_spy("Invitation") # => same as `class_double("Invitation").as_null_object`
object_spy("Invitation") # => same as `object_double("Invitation").as_null_object`
```

Verifying messages received in this way implements the Test Spy pattern.

```ruby
invitation = spy('invitation')

user.accept_invitation(invitation)

expect(invitation).to have_received(:accept)

# You can also use other common message expectations. For example:
expect(invitation).to have_received(:accept).with(mailer)
expect(invitation).to have_received(:accept).twice
expect(invitation).to_not have_received(:accept).with(mailer)

# One can specify a return value on the spy the same way one would a double.
invitation = spy('invitation', :accept => true)
expect(invitation).to have_received(:accept).with(mailer)
expect(invitation.accept).to eq(true)
```

Note that `have_received(...).with(...)` is unable to work properly when
passed arguments are mutated after the spy records the received message.
For example, this does not work properly:

```ruby
greeter = spy("greeter")

message = "Hello"
greeter.greet_with(message)
message << ", World"

expect(greeter).to have_received(:greet_with).with("Hello")
```

## Nomenclature

### Mock Objects and Test Stubs

The names Mock Object and Test Stub suggest specialized Test Doubles.  i.e.
a Test Stub is a Test Double that only supports method stubs, and a Mock
Object is a Test Double that supports message expectations and method
stubs.

There is a lot of overlapping nomenclature here, and there are many
variations of these patterns (fakes, spies, etc). Keep in mind that most of
the time we're talking about method-level concepts that are variations of
method stubs and message expectations, and we're applying to them to _one_
generic kind of object: a Test Double.

### Test-Specific Extension

a.k.a. Partial Double, a Test-Specific Extension is an extension of a
real object in a system that is instrumented with test-double like
behaviour in the context of a test. This technique is very common in Ruby
because we often see class objects acting as global namespaces for methods.
For example, in Rails:

```ruby
person = double("person")
allow(Person).to receive(:find) { person }
```

In this case we're instrumenting Person to return the person object we've
defined whenever it receives the `find` message. We can also set a message
expectation so that the example fails if `find` is not called:

```ruby
person = double("person")
expect(Person).to receive(:find) { person }
```

RSpec replaces the method we're stubbing or mocking with its own
test-double-like method. At the end of the example, RSpec verifies any message
expectations, and then restores the original methods.

## Expecting Arguments

```ruby
expect(double).to receive(:msg).with(*args)
expect(double).to_not receive(:msg).with(*args)
```

You can set multiple expectations for the same message if you need to:

```ruby
expect(double).to receive(:msg).with("A", 1, 3)
expect(double).to receive(:msg).with("B", 2, 4)
```

## Argument Matchers

Arguments that are passed to `with` are compared with actual arguments
received using ===. In cases in which you want to specify things about the
arguments rather than the arguments themselves, you can use any of the
matchers that ship with rspec-expectations. They don't all make syntactic
sense (they were primarily designed for use with RSpec::Expectations), but
you are free to create your own custom RSpec::Matchers.

rspec-mocks also adds some keyword Symbols that you can use to
specify certain kinds of arguments:

```ruby
expect(double).to receive(:msg).with(no_args)
expect(double).to receive(:msg).with(any_args)
expect(double).to receive(:msg).with(1, any_args) # any args acts like an arg splat and can go anywhere
expect(double).to receive(:msg).with(1, kind_of(Numeric), "b") #2nd argument can be any kind of Numeric
expect(double).to receive(:msg).with(1, boolean(), "b") #2nd argument can be true or false
expect(double).to receive(:msg).with(1, /abc/, "b") #2nd argument can be any String matching the submitted Regexp
expect(double).to receive(:msg).with(1, anything(), "b") #2nd argument can be anything at all
expect(double).to receive(:msg).with(1, duck_type(:abs, :div), "b") #2nd argument can be object that responds to #abs and #div
expect(double).to receive(:msg).with(hash_including(:a => 5)) # first arg is a hash with a: 5 as one of the key-values
expect(double).to receive(:msg).with(array_including(5)) # first arg is an array with 5 as one of the key-values
expect(double).to receive(:msg).with(hash_excluding(:a => 5)) # first arg is a hash without a: 5 as one of the key-values
```

## Receive Counts

```ruby
expect(double).to receive(:msg).once
expect(double).to receive(:msg).twice
expect(double).to receive(:msg).exactly(n).times
expect(double).to receive(:msg).at_least(:once)
expect(double).to receive(:msg).at_least(:twice)
expect(double).to receive(:msg).at_least(n).times
expect(double).to receive(:msg).at_most(:once)
expect(double).to receive(:msg).at_most(:twice)
expect(double).to receive(:msg).at_most(n).times
```

## Ordering

```ruby
expect(double).to receive(:msg).ordered
expect(double).to receive(:other_msg).ordered
  # This will fail if the messages are received out of order
```

This can include the same message with different arguments:

```ruby
expect(double).to receive(:msg).with("A", 1, 3).ordered
expect(double).to receive(:msg).with("B", 2, 4).ordered
```

## Setting Responses

Whether you are setting a message expectation or a method stub, you can
tell the object precisely how to respond. The most generic way is to pass
a block to `receive`:

```ruby
expect(double).to receive(:msg) { value }
```

When the double receives the `msg` message, it evaluates the block and returns
the result.

```ruby
expect(double).to receive(:msg).and_return(value)
expect(double).to receive(:msg).exactly(3).times.and_return(value1, value2, value3)
  # returns value1 the first time, value2 the second, etc
expect(double).to receive(:msg).and_raise(error)
  # error can be an instantiated object or a class
  # if it is a class, it must be instantiable with no args
expect(double).to receive(:msg).and_throw(:msg)
expect(double).to receive(:msg).and_yield(values, to, yield)
expect(double).to receive(:msg).and_yield(values, to, yield).and_yield(some, other, values, this, time)
  # for methods that yield to a block multiple times
```

Any of these responses can be applied to a stub as well

```ruby
allow(double).to receive(:msg).and_return(value)
allow(double).to receive(:msg).and_return(value1, value2, value3)
allow(double).to receive(:msg).and_raise(error)
allow(double).to receive(:msg).and_throw(:msg)
allow(double).to receive(:msg).and_yield(values, to, yield)
allow(double).to receive(:msg).and_yield(values, to, yield).and_yield(some, other, values, this, time)
```

## Arbitrary Handling

Once in a while you'll find that the available expectations don't solve the
particular problem you are trying to solve. Imagine that you expect the message
to come with an Array argument that has a specific length, but you don't care
what is in it. You could do this:

```ruby
expect(double).to receive(:msg) do |arg|
  expect(arg.size).to eq 7
end
```

If the method being stubbed itself takes a block, and you need to yield to it
in some special way, you can use this:

```ruby
expect(double).to receive(:msg) do |&arg|
  begin
    arg.call
  ensure
    # cleanup
  end
end
```

## Delegating to the Original Implementation

When working with a partial mock object, you may occasionally
want to set a message expectation without interfering with how
the object responds to the message. You can use `and_call_original`
to achieve this:

```ruby
expect(Person).to receive(:find).and_call_original
Person.find # => executes the original find method and returns the result
```

## Combining Expectation Details

Combining the message name with specific arguments, receive counts and responses
you can get quite a bit of detail in your expectations:

```ruby
expect(double).to receive(:<<).with("illegal value").once.and_raise(ArgumentError)
```

While this is a good thing when you really need it, you probably don't really
need it! Take care to specify only the things that matter to the behavior of
your code.

## Stubbing and Hiding Constants

See the [mutating constants
README](https://github.com/rspec/rspec-mocks/blob/master/features/mutating_constants/README.md)
for info on this feature.

## Use `before(:example)`, not `before(:context)`

Stubs in `before(:context)` are not supported. The reason is that all stubs and mocks get cleared out after each example, so any stub that is set in `before(:context)` would work in the first example that happens to run in that group, but not for any others.

Instead of `before(:context)`, use `before(:example)`.

## Settings mocks or stubs on any instance of a class

rspec-mocks provides two methods, `allow_any_instance_of` and
`expect_any_instance_of`, that will allow you to stub or mock any instance
of a class. They are used in place of `allow` or `expect`:

```ruby
allow_any_instance_of(Widget).to receive(:name).and_return("Wibble")
expect_any_instance_of(Widget).to receive(:name).and_return("Wobble")
```

These methods add the appropriate stub or expectation to all instances of
`Widget`.

This feature is sometimes useful when working with legacy code, though in
general we discourage its use for a number of reasons:

* The `rspec-mocks` API is designed for individual object instances, but this
  feature operates on entire classes of objects. As a result there are some
  semantically confusing edge cases. For example in
  `expect_any_instance_of(Widget).to receive(:name).twice` it isn't clear
  whether each specific instance is expected to receive `name` twice, or if two
  receives total are expected. (It's the former.)
* Using this feature is often a design smell. It may be
  that your test is trying to do too much or that the object under test is too
  complex.
* It is the most complicated feature of `rspec-mocks`, and has historically
  received the most bug reports. (None of the core team actively use it,
  which doesn't help.)


## Further Reading

There are many different viewpoints about the meaning of mocks and stubs. If
you are interested in learning more, here is some recommended reading:

* Mock Objects: http://www.mockobjects.com/
* Endo-Testing: http://www.ccs.neu.edu/research/demeter/related-work/extreme-programming/MockObjectsFinal.PDF
* Mock Roles, Not Objects: http://www.jmock.org/oopsla2004.pdf
* Test Double: http://www.martinfowler.com/bliki/TestDouble.html
* Test Double Patterns: http://xunitpatterns.com/Test%20Double%20Patterns.html
* Mocks aren't stubs: http://www.martinfowler.com/articles/mocksArentStubs.html

## Also see

* [https://github.com/rspec/rspec](https://github.com/rspec/rspec)
* [https://github.com/rspec/rspec-core](https://github.com/rspec/rspec-core)
* [https://github.com/rspec/rspec-expectations](https://github.com/rspec/rspec-expectations)
* [https://github.com/rspec/rspec-rails](https://github.com/rspec/rspec-rails)
