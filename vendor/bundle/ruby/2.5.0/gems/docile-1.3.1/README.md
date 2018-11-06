# Docile

[![Gem Version](https://img.shields.io/gem/v/docile.svg)](https://rubygems.org/gems/docile)
[![Gem Downloads](https://img.shields.io/gem/dt/docile.svg)](https://rubygems.org/gems/docile)

[![Join the chat at https://gitter.im/ms-ati/docile](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/ms-ati/docile?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Yard Docs](http://img.shields.io/badge/yard-docs-blue.svg)](http://rubydoc.info/github/ms-ati/docile)
[![Docs Coverage](http://inch-ci.org/github/ms-ati/docile.png)](http://inch-ci.org/github/ms-ati/docile)

[![Build Status](https://img.shields.io/travis/ms-ati/docile/master.svg)](https://travis-ci.org/ms-ati/docile)
[![Code Coverage](https://img.shields.io/codecov/c/github/ms-ati/docile.svg)](https://codecov.io/github/ms-ati/docile)
[![Maintainability](https://api.codeclimate.com/v1/badges/79ca631bc123f7b83b34/maintainability)](https://codeclimate.com/github/ms-ati/docile/maintainability)

Ruby makes it possible to create very expressive **Domain Specific
Languages**, or **DSL**'s for short. However, it requires some deep knowledge and
somewhat hairy meta-programming to get the interface just right.

"Docile" means *Ready to accept control or instruction; submissive* [[1]]

Instead of each Ruby project reinventing this wheel, let's make our Ruby DSL
coding a bit more docile...

[1]: http://www.google.com/search?q=docile+definition   "Google"

## Usage

### Basic: Ruby [Array](http://ruby-doc.org/core-2.2.2/Array.html) as DSL

Let's say that we want to make a DSL for modifying Array objects.
Wouldn't it be great if we could just treat the methods of Array as a DSL?

```ruby
with_array([]) do
  push 1
  push 2
  pop
  push 3
end
#=> [1, 3]
```

No problem, just define the method `with_array` like this:

```ruby
def with_array(arr=[], &block)
  Docile.dsl_eval(arr, &block)
end
```

Easy!

### Next step: Allow helper methods to call DSL methods

What if, in our use of the methods of Array as a DSL, we want to extract
helper methods which in turn call DSL methods?

```ruby
def pop_sum_and_push(n)
  sum = 0
  n.times { sum += pop }
  push sum
end

Docile.dsl_eval([]) do
  push 5
  push 6
  pop_sum_and_push(2)
end
#=> [11]
```

Without Docile, you may find this sort of code extraction to be more
challenging.

### Wait! Can't I do that with just `instance_eval` or `instance_exec`?

Good question!

In short: **No**. 

Not if you want the code in the block to be able to refer to anything
the block would normally have access to from the surrounding context.

Let's be very specific. Docile internally uses `instance_exec` (see [execution.rb#26](lib/docile/execution.rb#L26)), adding a small layer to support referencing *local variables*, *instance variables*, and *methods* from the _block's context_ **or** the target _object's context_, interchangeably. This is "**the hard part**", where most folks making a DSL in Ruby throw up their hands.

For example:

```ruby
class ContextOfBlock
  def example_of_contexts
    @block_instance_var = 1
    block_local_var = 2

    with_array do
      push @block_instance_var
      push block_local_var
      pop
      push block_sees_this_method 
    end
  end
  
  def block_sees_this_method
    3
  end  

  def with_array(&block)
    {
      docile: Docile.dsl_eval([], &block),
      instance_eval: ([].instance_eval(&block) rescue $!),
      instance_exec: ([].instance_exec(&block) rescue $!)
    }  
  end
end

ContextOfBlock.new.example_of_contexts
#=> {
      :docile=>[1, 3],
      :instance_eval=>#<NameError: undefined local variable or method `block_sees_this_method' for [nil]:Array>,
      :instance_exec=>#<NameError: undefined local variable or method `block_sees_this_method' for [nil]:Array>
    }
```

As you can see, it won't be possible to call methods or access instance variables defined in the block's context using just the raw `instance_eval` or `instance_exec` methods. And in fact, Docile goes further, making it easy to maintain this support even in multi-layered DSLs.

### Build a Pizza

Mutating (changing) an Array instance is fine, but what usually makes a good DSL is a [Builder Pattern][2].

For example, let's say you want a DSL to specify how you want to build a Pizza:

```ruby
@sauce_level = :extra

pizza do
  cheese
  pepperoni
  sauce @sauce_level
end
#=> #<Pizza:0x00001009dc398 @cheese=true, @pepperoni=true, @bacon=false, @sauce=:extra>
```

And let's say we have a PizzaBuilder, which builds a Pizza like this:

```ruby
Pizza = Struct.new(:cheese, :pepperoni, :bacon, :sauce)

class PizzaBuilder
  def cheese(v=true); @cheese = v; self; end
  def pepperoni(v=true); @pepperoni = v; self; end
  def bacon(v=true); @bacon = v; self; end
  def sauce(v=nil); @sauce = v; self; end
  def build
    Pizza.new(!!@cheese, !!@pepperoni, !!@bacon, @sauce)
  end
end

PizzaBuilder.new.cheese.pepperoni.sauce(:extra).build
#=> #<Pizza:0x00001009dc398 @cheese=true, @pepperoni=true, @bacon=false, @sauce=:extra>
```

Then implement your DSL like this:

```ruby
def pizza(&block)
  Docile.dsl_eval(PizzaBuilder.new, &block).build
end
```

It's just that easy!

[2]: http://stackoverflow.com/questions/328496/when-would-you-use-the-builder-pattern  "Builder Pattern"

### Multi-level and Recursive DSLs

Docile is a very easy way to write a multi-level DSL in Ruby, even for
a [recursive data structure such as a tree][4]:

```ruby
Person = Struct.new(:name, :mother, :father)

person {
  name 'John Smith'
  mother {
    name 'Mary Smith'
  }
  father {
    name 'Tom Smith'
    mother {
      name 'Jane Smith'
    }
  }
}

#=> #<struct Person name="John Smith",
#                   mother=#<struct Person name="Mary Smith", mother=nil, father=nil>,
#                   father=#<struct Person name="Tom Smith",
#                                          mother=#<struct Person name="Jane Smith", mother=nil, father=nil>,
#                                          father=nil>>
```

See the full [person tree example][4] for details.

[4]: https://gist.github.com/ms-ati/2bb17bdf10a430faba98

### Block parameters

Parameters can be passed to the DSL block.

Supposing you want to make some sort of cheap [Sinatra][3] knockoff:

```ruby
@last_request = nil
respond '/path' do |request|
  puts "Request received: #{request}"
  @last_request = request
end

def ride bike
  # Play with your new bike
end

respond '/new_bike' do |bike|
  ride(bike)
end
```

You'd put together a dispatcher something like this:

```ruby
require 'singleton'

class DispatchScope
  def a_method_you_can_call_from_inside_the_block
    :useful_huh?
  end
end

class MessageDispatch
  include Singleton

  def initialize
    @responders = {}
  end

  def add_responder path, &block
    @responders[path] = block
  end

  def dispatch path, request
    Docile.dsl_eval(DispatchScope.new, request, &@responders[path])
  end
end

def respond path, &handler
  MessageDispatch.instance.add_responder path, handler
end

def send_request path, request
  MessageDispatch.instance.dispatch path, request
end
```

[3]: http://www.sinatrarb.com "Sinatra"

### Functional-Style Immutable DSL Objects

Sometimes, you want to use an object as a DSL, but it doesn't quite fit the
[imperative](http://en.wikipedia.org/wiki/Imperative_programming) pattern shown
above.

Instead of methods like
[Array#push](http://www.ruby-doc.org/core-2.0/Array.html#method-i-push), which
modifies the object at hand, it has methods like
[String#reverse](http://www.ruby-doc.org/core-2.0/String.html#method-i-reverse),
which returns a new object without touching the original. Perhaps it's even
[frozen](http://www.ruby-doc.org/core-2.0/Object.html#method-i-freeze) in
order to enforce [immutability](http://en.wikipedia.org/wiki/Immutable_object).

Wouldn't it be great if we could just treat these methods as a DSL as well?

```ruby
s = "I'm immutable!".freeze

with_immutable_string(s) do
  reverse
  upcase
end
#=> "!ELBATUMMI M'I"

s
#=> "I'm immutable!"
```

No problem, just define the method `with_immutable_string` like this:

```ruby
def with_immutable_string(str="", &block)
  Docile.dsl_eval_immutable(str, &block)
end
```

All set!

### Accessing the block's return value

Sometimes you might want to access the return value of your provided block,
as opposed to the DSL object itself. In these cases, use
`dsl_eval_with_block_return`. It behaves exactly like `dsl_eval`, but returns
the output from executing the block, rather than the DSL object.

```ruby
arr = []
with_array(arr) do
  push "a"
  push "b"
  push "c"
  length
end
#=> 3

arr
#=> ["a", "b", "c"]
```

```ruby
def with_array(arr=[], &block)
  Docile.dsl_eval_with_block_return(arr, &block)
end
```

## Features

  1.  Method lookup falls back from the DSL object to the block's context
  2.  Local variable lookup falls back from the DSL object to the block's
        context
  3.  Instance variables are from the block's context only
  4.  Nested DSL evaluation, correctly chaining method and variable handling
        from the inner to the outer DSL scopes
  5.  Alternatives for both imperative and functional styles of DSL objects

## Installation

``` bash
$ gem install docile
```

## Links
* [Source](https://github.com/ms-ati/docile)
* [Documentation](http://rubydoc.info/gems/docile)
* [Bug Tracker](https://github.com/ms-ati/docile/issues)

## Status

Works on [all ruby versions since 1.8.7](https://github.com/ms-ati/docile/blob/master/.travis.yml), or so Travis CI [tells us](https://travis-ci.org/ms-ati/docile).

Used by some pretty cool gems to implement their DSLs, notably including [SimpleCov](https://github.com/colszowka/simplecov). Keep an eye out for new gems using Docile at the [Ruby Toolbox](https://www.ruby-toolbox.com/projects/docile).

## Release Policy

Docile releases follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Note on Patches/Pull Requests

  * Fork the project.
  * Setup your development environment with:
      `gem install bundler; bundle install`
  * Make your feature addition or bug fix.
  * Add tests for it. This is important so I don't break it in a future version
      unintentionally.
  * Commit, do not mess with rakefile, version, or history.
      (if you want to have your own version, that is fine but bump version in a
      commit by itself I can ignore when I pull)
  * Send me a pull request. Bonus points for topic branches.

## Copyright & License

Copyright (c) 2012-2018 Marc Siegel.

Licensed under the [MIT License](http://choosealicense.com/licenses/mit/), see [LICENSE](LICENSE) for details.


