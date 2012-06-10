Slop
====

Slop is a simple, lightweight option parser with an easy to remember syntax and friendly API.

Note that this is the `v2` branch. If you are looking for version 3 of Slop
please check out the [master branch](https://github.com/injekt/slop).

Installation
------------

### Rubygems

    gem install slop

### GitHub

    git clone git://github.com/injekt/slop.git
    gem build slop.gemspec
    gem install slop-<version>.gem

Usage
-----

```ruby
# parse assumes ARGV, otherwise you can pass it your own Array
opts = Slop.parse do
  on :v, :verbose, 'Enable verbose mode'   # A boolean option
  on :n, :name=, 'Your name'               # This option requires an argument
  on :s, :sex, 'Your sex', true            # So does this one
  on :a, :age, 'Your age', optional: true  # This one accepts an optional argument
  on '-D', '--debug', 'Enable debug'       # The prefixed -'s are optional
end

# if ARGV is `-v --name 'lee jarvis' -s male`
opts.verbose? #=> true
opts.name?    #=> true
opts[:name]   #=> 'lee jarvis'
opts.age?     #=> false
opts[:age]    #=> nil
```

For more information about creating options, see the
[Creating Options](https://github.com/injekt/slop/wiki/Creating-Options---v2)
wiki page.

You can also return your options as a Hash

```ruby
opts.to_hash #=> { :name => 'Lee Jarvis', :verbose => true, :age => nil, :sex => 'male' }
```

If you want some pretty output for the user to see your options, you can just
send the Slop object to `puts` or use the `help` method.

```ruby
puts opts
puts opts.help
```

Will output something like

```
-v, --verbose      Enable verbose mode
-n, --name         Your name
-a, --age          Your age
```

You can also add a banner using the `banner` method

```ruby
opts = Slop.parse do
  banner "Usage: foo.rb [options]"
end
```

Helpful Help
------------

Long form:

```ruby
Slop.parse do
  ...
  on :h, :help, 'Print this help message', :tail => true do
    puts help
    exit
  end
end
```

Shortcut:

```ruby
Slop.new :help => true
# or
Slop.new :help
```

Parsing
-------

Slop's pretty good at parsing, let's take a look at what it'll extract for you

```ruby
Slop.parse(:multiple_switches => false) do
  on 's', 'server='
  on 'p', 'port=', :as => :integer
  on 'username=', :matches => /^[a-zA-Z]+$/
  on 'password='
end
```

Now throw some options at it:

```
-s ftp://foobar.com -p1234 --username=FooBar --password 'hello there'
```

Here's what we'll get back

```
{
  :server => "ftp://foobar.com",
  :port => 1234,
  :username => "FooBar",
  :password => "hello there"
}
```

Events
------

If you'd like to trigger an event when an option is used, you can pass a
block to your option. Here's how:

```ruby
Slop.parse do
  on :V, :version, 'Print the version' do
    puts 'Version 1.0.0'
    exit
  end
end
```

Now when using the `--version` option on the command line, the trigger will
be called and its contents executed.

Yielding Non Options
--------------------

If you pass a block to `Slop#parse`, Slop will yield non-options as
they're found, just like
[OptionParser](http://rubydoc.info/stdlib/optparse/1.9.2/OptionParser:order)
does it.

```ruby
opts = Slop.new do
  on :n, :name, :optional => false
end

opts.parse do |arg|
  puts arg
end

# if ARGV is `foo --name Lee bar`
foo
bar
```

Negative Options
----------------

Slop also allows you to prefix `--no-` to an option which will force the option
to return a false value.

```ruby
opts = Slop.parse do
  on :v, :verbose, :default => true
end

# with no command line options
opts[:verbose] #=> true

# with `--no-verbose`
opts[:verbose] #=> false
opts.verbose?  #=> false
```

Short Switches
--------------

Want to enable multiple switches at once like rsync does? By default Slop will
parse `-abc` as the options `a` `b` and `c` and set their values to true. If
you would like to disable this, you can pass `multiple_switches => false` to
a new Slop object. In which case Slop will then parse `-fbar` as the option
`f` with the argument value `bar`.

```ruby
Slop.parse do
  on :a, 'First switch'
  on :b, 'Second switch'
  on :c, 'Third switch'
end

# Using `-ac`
opts[:a] #=> true
opts[:b] #=> false
opts[:c] #=> true

Slop.parse(:multiple_switches => false) do
  on :a, 'Some switch', true
end

# Using `ahello`
opts[:a] #=> 'hello'
```

Lists
-----

You can of course also parse lists into options. Here's how:

```ruby
opts = Slop.parse do
  opt :people, true, :as => Array
end

# ARGV is `--people lee,john,bill`
opts[:people] #=> ['lee', 'john', 'bill']
```

Slop supports a few styles of list parsing. Check out
[this wiki page](https://github.com/injekt/slop/wiki/Lists---v2) for more info.

Strict Mode
-----------

Passing `strict => true` to `Slop.parse` causes it to raise a `Slop::InvalidOptionError`
when an invalid option is found (`false` by default):

```ruby
Slop.new(:strict => true).parse(%w/--foo/)
# => Slop::InvalidOptionError: Unknown option -- 'foo'
```

Features
--------

Check out the following wiki pages for more features:

* [Ranges](https://github.com/injekt/slop/wiki/Ranges)
* [Auto Create](https://github.com/injekt/slop/wiki/Auto-Create)
* [Commands](https://github.com/injekt/slop/wiki/Commands---v2)

Woah woah, why you hating on OptionParser?
------------------------------------------

I'm not, honestly! I love OptionParser. I really do, it's a fantastic library.
So why did I build Slop? Well, I find myself using OptionParser to simply
gather a bunch of key/value options, usually you would do something like this:

```ruby
require 'optparse'

things = {}

opt = OptionParser.new do |opt|
  opt.on('-n', '--name NAME', 'Your name') do |name|
    things[:name] = name
  end

  opt.on('-a', '--age AGE', 'Your age') do |age|
    things[:age] = age.to_i
  end

  # you get the point
end

opt.parse
things #=> { :name => 'lee', :age => 105 }
```

Which is all great and stuff, but it can lead to some repetition. The same
thing in Slop:

```ruby
require 'slop'

opts = Slop.parse do
  on :n, :name=, 'Your name'
  on :a, :age=, 'Your age', :as => :int
end

opts.to_hash #=> { :name => 'lee', :age => 105 }
```
