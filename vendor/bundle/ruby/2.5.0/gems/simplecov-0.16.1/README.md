SimpleCov [![Build Status](https://travis-ci.org/colszowka/simplecov.svg)][Continuous Integration] [![Dependency Status](https://gemnasium.com/colszowka/simplecov.svg)][Dependencies] [![Code Climate](https://codeclimate.com/github/colszowka/simplecov.svg)](https://codeclimate.com/github/colszowka/simplecov) [![Inline docs](http://inch-ci.org/github/colszowka/simplecov.svg)](http://inch-ci.org/github/colszowka/simplecov)
=========
**Code coverage for Ruby**

  * [Source Code]
  * [API documentation]
  * [Changelog]
  * [Rubygem]
  * [Continuous Integration]

[Coverage]: http://www.ruby-doc.org/stdlib-2.1.0/libdoc/coverage/rdoc/Coverage.html "API doc for Ruby's Coverage library"
[Source Code]: https://github.com/colszowka/simplecov "Source Code @ GitHub"
[API documentation]: http://rubydoc.info/gems/simplecov/frames "RDoc API Documentation at Rubydoc.info"
[Configuration]: http://rubydoc.info/gems/simplecov/SimpleCov/Configuration "Configuration options API documentation"
[Changelog]: https://github.com/colszowka/simplecov/blob/master/CHANGELOG.md "Project Changelog"
[Rubygem]: http://rubygems.org/gems/simplecov "SimpleCov @ rubygems.org"
[Continuous Integration]: http://travis-ci.org/colszowka/simplecov "SimpleCov is built around the clock by travis-ci.org"
[Dependencies]: https://gemnasium.com/colszowka/simplecov "SimpleCov dependencies on Gemnasium"
[simplecov-html]: https://github.com/colszowka/simplecov-html "SimpleCov HTML Formatter Source Code @ GitHub"

SimpleCov is a code coverage analysis tool for Ruby. It uses [Ruby's built-in Coverage][Coverage] library to gather code
coverage data, but makes processing its results much easier by providing a clean API to filter, group, merge, format,
and display those results, giving you a complete code coverage suite that can be set up with just a couple lines of
code.

In most cases, you'll want overall coverage results for your projects, including all types of tests, Cucumber features,
etc. SimpleCov automatically takes care of this by caching and merging results when generating reports, so your
report actually includes coverage across your test suites and thereby gives you a better picture of blank spots.

The official formatter of SimpleCov is packaged as a separate gem called [simplecov-html], but will be installed and configured
automatically when you launch SimpleCov. If you're curious, you can find it [on GitHub, too][simplecov-html].


## Contact

*Code and Bug Reports*

* [Issue Tracker](https://github.com/colszowka/simplecov/issues)
* See [CONTRIBUTING](https://github.com/colszowka/simplecov/blob/master/CONTRIBUTING.md) for how to contribute along with some common problems to check out before creating an issue.

*Questions, Problems, Suggestions, etc.*

* [Mailing List](https://groups.google.com/forum/#!forum/simplecov) "Open mailing list for discussion and announcements on Google Groups"

Getting started
---------------
1. Add SimpleCov to your `Gemfile` and `bundle install`:

    ```ruby
    gem 'simplecov', require: false, group: :test
    ```
2. Load and launch SimpleCov **at the very top** of your `test/test_helper.rb`
   (*or `spec_helper.rb`, `rails_helper`, cucumber `env.rb`, or whatever your preferred test
   framework uses*):

    ```ruby
    require 'simplecov'
    SimpleCov.start

    # Previous content of test helper now starts here
    ```

    **Note:** If SimpleCov starts after your application code is already loaded
    (via `require`), it won't be able to track your files and their coverage!
    The `SimpleCov.start` **must** be issued **before any of your application
    code is required!**

    SimpleCov must be running in the process that you want the code coverage
    analysis to happen on. When testing a server process (e.g. a JSON API
    endpoint) via a separate test process (e.g. when using Selenium) where you
    want to see all code executed by the `rails server`, and not just code
    executed in your actual test files, you'll want to add something like this
    to the top of `script/rails` (or `bin/rails` for Rails 4), but below the
    "shebang" line (`#! /usr/bin/env ruby`):

    ```ruby
    if ENV['RAILS_ENV'] == 'test'
      require 'simplecov'
      SimpleCov.start 'rails'
      puts "required simplecov"
    end
    ```

3. Run your tests, open up `coverage/index.html` in your browser and check out
   what you've missed so far.
4. Add the following to your `.gitignore` file to ensure that coverage results
   are not tracked by Git (optional):

    ```
    coverage
    ```

    If you're making a Rails application, SimpleCov comes with built-in configurations (see below for information on profiles)
    that will get you started with groups for your Controllers, Views, Models and Helpers. To use it, the first two lines of
    your test_helper should be like this:

    ```ruby
    require 'simplecov'
    SimpleCov.start 'rails'
    ```

## Example output

**Coverage results report, fully browsable locally with sorting and much more:**

![SimpleCov coverage report](https://cloud.githubusercontent.com/assets/137793/17071162/db6f253e-502d-11e6-9d84-e40c3d75f333.png)


**Source file coverage details view:**

![SimpleCov source file detail view](https://cloud.githubusercontent.com/assets/137793/17071163/db6f9f0a-502d-11e6-816c-edb2c66fad8d.png)

## Use it with any framework!

Similarly to the usage with Test::Unit described above, the only thing you have to do is to add the SimpleCov
config to the very top of your Cucumber/RSpec/whatever setup file.

Add the setup code to the **top** of `features/support/env.rb` (for Cucumber) or `spec/spec_helper.rb` (for RSpec).
Other test frameworks should work accordingly, whatever their setup file may be:

```ruby
require 'simplecov'
SimpleCov.start 'rails'
```

You could even track what kind of code your UI testers are touching if you want to go overboard with things. SimpleCov does not
care what kind of framework it is running in; it just looks at what code is being executed and generates a report about it.

### Notes on specific frameworks and test utilities

For some frameworks and testing tools there are quirks and problems you might want to know about if you want
to use SimpleCov with them. Here's an overview of the known ones:

<table>
  <tr><th>Framework</th><th>Notes</th><th>Issue</th></tr>
  <tr>
    <th>
      bootsnap
    </th>
    <td>
      <a href="#want-to-use-bootsnap-with-simplecov">See section below.</a>
    </td>
    <td>
      <a href="https://github.com/Shopify/bootsnap/issues/35">Shopify/bootsnap#35</a>
    </td>
  </tr>
  <tr>
    <th>
      parallel_tests
    </th>
    <td>
      As of 0.8.0, SimpleCov should correctly recognize parallel_tests and
      supplement your test suite names with their corresponding test env
      numbers. SimpleCov locks the resultset cache while merging, ensuring no
      race conditions occur when results are merged.
    </td>
    <td>
      <a href="https://github.com/colszowka/simplecov/issues/64">#64</a> &amp;
      <a href="https://github.com/colszowka/simplecov/pull/185">#185</a>
    </td>
  </tr>
  <tr>
    <th>
      RubyMine
    </th>
    <td>
      The <a href="https://www.jetbrains.com/ruby/">RubyMine IDE</a> has
      built-in support for SimpleCov's coverage reports, though you might need
      to explicitly set the output root using `SimpleCov.root('foo/bar/baz')`
    </td>
    <td>
      <a href="https://github.com/colszowka/simplecov/issues/95">#95</a>
    </td>
  </tr>
  <tr>
    <th>
      Spork
    </th>
    <td>
      Because of how Spork works internally (using preforking), there used to
      be trouble when using SimpleCov with it, but that has apparently been
      resolved with a specific configuration strategy. See <a
      href="https://github.com/colszowka/simplecov/issues/42#issuecomment-4440284">this</a>
      comment.
    </td>
    <td>
      <a href="https://github.com/colszowka/simplecov/issues/42#issuecomment-4440284">#42</a>
    </td>
  </tr>
  <tr>
    <th>
      Spring
    </th>
    <td>
      <a href="#want-to-use-spring-with-simplecov">See section below.</a>
    </td>
    <td>
      <a href="https://github.com/colszowka/simplecov/issues/381">#381</a>
    </td>
  </tr>
  <tr>
    <th>
      Test/Unit
    </th>
    <td>
      Test Unit 2 used to mess with ARGV, leading to a failure to detect the
      test process name in SimpleCov. <code>test-unit</code> releases 2.4.3+
      (Dec 11th, 2011) should have this problem resolved.
    </td>
    <td>
      <a href="https://github.com/colszowka/simplecov/issues/45">#45</a> &amp;
      <a href="https://github.com/test-unit/test-unit/pull/12">test-unit/test-unit#12</a>
    </td>
  </tr>
</table>

## Configuring SimpleCov

[Configuration] settings can be applied in three formats, which are completely equivalent:

* The most common way is to configure it directly in your start block:

    ```ruby
    SimpleCov.start do
      some_config_option 'foo'
    end
    ```
* You can also set all configuration options directly:

    ```ruby
    SimpleCov.some_config_option 'foo'
    ```
* If you do not want to start coverage immediately after launch or want to add additional configuration later on in a concise way, use:

    ```ruby
    SimpleCov.configure do
      some_config_option 'foo'
    end
    ```

Please check out the [Configuration] API documentation to find out what you can customize.

## Using .simplecov for centralized config

If you use SimpleCov to merge multiple test suite results (e.g. Test/Unit and Cucumber) into a single report, you'd normally have to
set up all your config options twice, once in `test_helper.rb` and once in `env.rb`.

To avoid this, you can place a file called `.simplecov` in your project root. You can then just leave the `require 'simplecov'` in each
test setup helper (**at the top**) and move the `SimpleCov.start` code with all your custom config options into `.simplecov`:

```ruby
# test/test_helper.rb
require 'simplecov'

# features/support/env.rb
require 'simplecov'

# .simplecov
SimpleCov.start 'rails' do
  # any custom configs like groups and filters can be here at a central place
end
```

Using `.simplecov` rather than separately requiring SimpleCov multiple times is recommended if you are merging multiple test frameworks like Cucumber and RSpec that rely on each other, as invoking SimpleCov multiple times can cause coverage information to be lost.

## Filters

Filters can be used to remove selected files from your coverage data. By default, a filter is applied that removes all files
OUTSIDE of your project's root directory - otherwise you'd end up with billions of coverage reports for source files in the
gems you are using.

You can define your own to remove things like configuration files, tests or whatever you don't need in your coverage
report.

### Defining custom filters

You can currently define a filter using either a String or Regexp (that will then be Regexp-matched against each source file's path),
a block or by passing in your own Filter class.

#### String filter

```ruby
SimpleCov.start do
  add_filter "/test/"
end
```

This simple string filter will remove all files that match "/test/" in their path.

#### Regex filter

```ruby
SimpleCov.start do
  add_filter %r{^/test/}
end
```

This simple regex filter will remove all files that start with /test/ in their path.

#### Block filter

```ruby
SimpleCov.start do
  add_filter do |source_file|
    source_file.lines.count < 5
  end
end
```

Block filters receive a SimpleCov::SourceFile instance and expect your block to return either true (if the file is to be removed
from the result) or false (if the result should be kept). Please check out the RDoc for SimpleCov::SourceFile to learn about the
methods available to you. In the above example, the filter will remove all files that have less than 5 lines of code.

#### Custom filter class

```ruby
class LineFilter < SimpleCov::Filter
  def matches?(source_file)
    source_file.lines.count < filter_argument
  end
end

SimpleCov.add_filter LineFilter.new(5)
```

Defining your own filters is pretty easy: Just inherit from SimpleCov::Filter and define a method 'matches?(source_file)'. When running
the filter, a true return value from this method will result in the removal of the given source_file. The filter_argument method
is being set in the SimpleCov::Filter initialize method and thus is set to 5 in this example.

#### Array filter

```ruby
SimpleCov.start do
  proc = Proc.new { |source_file| false }
  add_filter ["string", /regex/, proc, LineFilter.new(5)]
end
```

You can pass in an array containing any of the other filter types.

#### Ignoring/skipping code

You can exclude code from the coverage report by wrapping it in `# :nocov:`.

```ruby
# :nocov:
def skip_this_method
  never_reached
end
# :nocov:
```

The name of the token can be changed to your liking. [Learn more about the nocov feature.]( https://github.com/colszowka/simplecov/blob/master/features/config_nocov_token.feature)

**Note:** You shouldn't have to use the nocov token to skip private methods that are being included in your coverage. If you appropriately test the public interface of your classes and objects you should automatically get full coverage of your private methods.

## Default root filter and coverage for things outside of it

By default, SimpleCov filters everything outside of the `SimpleCov.root` directory. However, sometimes you may want
to include coverage reports for things you include as a gem, for example a Rails Engine.

Here's an example by [@lsaffie](https://github.com/lsaffie) from [#221](https://github.com/colszowka/simplecov/issues/221)
that shows how you can achieve just that:

```ruby
SimpleCov.start :rails do
  filters.clear # This will remove the :root_filter and :bundler_filter that come via simplecov's defaults
  add_filter do |src|
    !(src.filename =~ /^#{SimpleCov.root}/) unless src.filename =~ /my_engine/
  end
end
```

## Groups

You can separate your source files into groups. For example, in a Rails app, you'll want to have separate listings for
Models, Controllers, Helpers, and Libs. Group definition works similarly to Filters (and also accepts custom
filter classes), but source files end up in a group when the filter passes (returns true), as opposed to filtering results,
which exclude files from results when the filter results in a true value.

Add your groups with:

```ruby
SimpleCov.start do
  add_group "Models", "app/models"
  add_group "Controllers", "app/controllers"
  add_group "Long files" do |src_file|
    src_file.lines.count > 100
  end
  add_group "Multiple Files", ["app/models", "app/controllers"] # You can also pass in an array
  add_group "Short files", LineFilter.new(5) # Using the LineFilter class defined in Filters section above
end
```

## Merging results

You normally want to have your coverage analyzed across ALL of your test suites, right?

Simplecov automatically caches coverage results in your (coverage_path)/.resultset.json. Those results will then
be automatically merged when generating the result, so when coverage is set up properly for Cucumber and your
unit / functional / integration tests, all of those test suites will be taken into account when building the
coverage report.

There are two things to note here though:

### Test suite names

SimpleCov tries to guess the name of the currently running test suite based upon the shell command the tests
are running on. This should work fine for Unit Tests, RSpec, and Cucumber. If it fails, it will use the shell
command that invoked the test suite as a command name.

If you have some non-standard setup and still want nicely labeled test suites, you have to give Simplecov a
cue as to what the name of the currently running test suite is. You can do so by specifying
`SimpleCov.command_name` in one test file that is part of your specific suite.

To customize the suite names on a Rails app (yeah, sorry for being Rails-biased, but everyone knows what
the structure of those projects is. You can apply this accordingly to the RSpecs in your
Outlook-WebDAV-Calendar-Sync gem), you could do something like this:

```ruby
# test/unit/some_test.rb
SimpleCov.command_name 'test:units'

# test/functionals/some_controller_test.rb
SimpleCov.command_name "test:functionals"

# test/integration/some_integration_test.rb
SimpleCov.command_name "test:integration"

# features/support/env.rb
SimpleCov.command_name "features"
```

Note that this only has to be invoked ONCE PER TEST SUITE, so even if you have 200 unit test files,
specifying it in `some_test.rb` is enough.

Last but not least **if multiple suites resolve to the same `command_name`** be aware that the coverage results **will
clobber each other instead of being merged**.  SimpleCov is smart enough to detect unique names for the most common
setups, but if you have more than one test suite that doesn't follow a common pattern then you will want to manually
ensure that each suite gets a unique `command_name`.

If you are running tests in parallel each process has the potential to clobber results from the other test processes.
If you are relying on the default `command_name` then SimpleCov will attempt to detect and avoid parallel test suite
`command_name` collisions based on the presence of `ENV['PARALLEL_TEST_GROUPS']` and `ENV['TEST_ENV_NUMBER']`.  If your
parallel test runner does not set one or both of these then *you must* set a `command_name` and ensure that it is unique
per process (eg. `command_name "Unit Tests PID #{$$}"`).

If you are using parallel_tests, you must incorporate `TEST_ENV_NUMBER` into the command name yourself, in
order for SimpleCov to merge the results correctly. For example:

```ruby
# spec/spec_helper.rb
SimpleCov.command_name "features" + (ENV['TEST_ENV_NUMBER'] || '')
```

[simplecov-html] prints the used test suites in the footer of the generated coverage report.

### Timeout for merge

Of course, your cached coverage data is likely to become invalid at some point. Thus, result sets that are older than
`SimpleCov.merge_timeout` will not be used any more. By default, the timeout is 600 seconds (10 minutes), and you can
raise (or lower) it by specifying `SimpleCov.merge_timeout 3600` (1 hour), or, inside a configure/start block, with
just `merge_timeout 3600`.

You can deactivate merging altogether with `SimpleCov.use_merging false`.

## Running coverage only on demand

The Ruby STDLIB Coverage library that SimpleCov builds upon is *very* fast (on a ~10 min Rails test suite, the speed drop was
only a couple seconds for me), and therefore it's SimpleCov's policy to just generate coverage every time you run your tests because
it doesn't do your test speed any harm and you're always equipped with the latest and greatest coverage results.

Because of this, SimpleCov has no explicit built-in mechanism to run coverage only on demand.

However, you can still accomplish this very easily by introducing an ENV variable conditional into your SimpleCov setup block, like this:

```ruby
SimpleCov.start if ENV["COVERAGE"]
```

Then, SimpleCov will only run if you execute your tests like this:

```shell
COVERAGE=true rake test
```

## Profiles

By default, SimpleCov's only config assumption is that you only want coverage reports for files inside your project
root. To save yourself from repetitive configuration, you can use predefined blocks of configuration, called 'profiles',
or define your own.

You can then pass the name of the profile to be used as the first argument to SimpleCov.start. For example, simplecov
comes bundled with a 'rails' profile. It looks somewhat like this:

```ruby
SimpleCov.profiles.define 'rails' do
  add_filter '/test/'
  add_filter '/config/'

  add_group 'Controllers', 'app/controllers'
  add_group 'Models', 'app/models'
  add_group 'Helpers', 'app/helpers'
  add_group 'Libraries', 'lib'
end
```

As you can see, it's just a SimpleCov.configure block. In your test_helper.rb, launch SimpleCov with:

```ruby
SimpleCov.start 'rails'
```

or

```ruby
SimpleCov.start 'rails' do
  # additional config here
end
```

### Custom profiles

You can load additional profiles with the SimpleCov.load_profile('xyz') method. This allows you to build upon an existing
profile and customize it so you can reuse it in unit tests and Cucumber features. For example:

```ruby
# lib/simplecov_custom_profile.rb
require 'simplecov'
SimpleCov.profiles.define 'myprofile' do
  load_profile 'rails'
  add_filter 'vendor' # Don't include vendored stuff
end

# features/support/env.rb
require 'simplecov_custom_profile'
SimpleCov.start 'myprofile'

# test/test_helper.rb
require 'simplecov_custom_profile'
SimpleCov.start 'myprofile'
```

## Customizing exit behaviour

You can define what SimpleCov should do when your test suite finishes by customizing the at_exit hook:

```ruby
SimpleCov.at_exit do
  SimpleCov.result.format!
end
```

Above is the default behaviour. Do whatever you like instead!

### Minimum coverage

You can define the minimum coverage percentage expected. SimpleCov will return non-zero if unmet.

```ruby
SimpleCov.minimum_coverage 90
```

### Minimum coverage by file

You can define the minimum coverage by file percentage expected. SimpleCov will return non-zero if unmet. This is useful to help ensure coverage is relatively consistent, rather than being skewed by particularly good or bad areas of the code.

```ruby
SimpleCov.minimum_coverage_by_file 80
```

### Maximum coverage drop

You can define the maximum coverage drop percentage at once. SimpleCov will return non-zero if exceeded.

```ruby
SimpleCov.maximum_coverage_drop 5
```

### Refuse dropping coverage

You can also entirely refuse dropping coverage between test runs:

```ruby
SimpleCov.refuse_coverage_drop
```

## Using your own formatter

You can use your own formatter with:

```ruby
SimpleCov.formatter = SimpleCov::Formatter::HTMLFormatter
```

When calling SimpleCov.result.format!, it will be invoked with SimpleCov::Formatter::YourFormatter.new.format(result), "result"
being an instance of SimpleCov::Result. Do whatever your wish with that!


## Using multiple formatters

As of SimpleCov 0.9, you can specify multiple result formats:

```ruby
SimpleCov.formatters = SimpleCov::Formatter::MultiFormatter.new([
  SimpleCov::Formatter::HTMLFormatter,
  SimpleCov::Formatter::CSVFormatter,
])
```

## Available formatters, editor integrations and hosted services

  * [Open Source formatter and integration plugins for SimpleCov](doc/alternate-formatters.md)
  * [Editor Integration](doc/editor-integration.md)
  * [Hosted (commercial) services](doc/commercial-services.md)

## Ruby version compatibility

Only Ruby 1.9+ ships with the coverage library that SimpleCov depends upon and that's what SimpleCov supports. Additionally JRuby 9.1+ is supported as well, while JRuby 1.7 and 9.0 should work they're not "officially" supported.
SimpleCov is also built against Ruby 1.8 in [Continuous Integration], but this happens only to ensure that SimpleCov
does not make your test suite crash right now.

SimpleCov is built in [Continuous Integration] on Ruby 1.9.3, 2.0.0, 2.1, 2.2, 2.3, 2.4, 2.5 as well as JRuby 9.1.

## Want to find dead code in production?

Try [Coverband](https://github.com/danmayer/coverband).

## Want to use Spring with SimpleCov?

If you're using [Spring](https://github.com/rails/spring) to speed up test suite runs and want to run SimpleCov along with them, you'll find that it often misreports coverage with the default config due to some sort of eager loading issue. Don't despair!

1. Change the following settings in `test.rb`.

    ```ruby
    # For Rails
    # Do not eager load code on boot
    config.eager_load = false
    ```
2. Add your SimpleCov config, as you normally would, to your `spec_helper.rb`
   (or `rails_helper.rb` for RSpec 3). If you have a `config/spring.rb` file
   (or anything similar), add it to the start of such file. Here's a simple
   version of what the config should look like:

    ```ruby
    if ENV['RAILS_ENV'] == 'test'
      require 'simplecov'
      SimpleCov.start
    end
    ```
3. Run `spring rspec <path>` as normal. Remember to run `spring stop` after
   making important changes to your app or its specs!

## Want to use bootsnap with SimpleCov?

As mentioned in [this issue](https://github.com/Shopify/bootsnap/issues/35) iseq
loading/dumping doesn't work with coverage. Hence you need to deactivate it when
you run coverage so for instance when you use the environment `COVERAGE=true` to
decide that you want to gather coverage you can do:

```ruby
Bootsnap.setup(
  compile_cache_iseq:   !ENV["COVERAGE"], # Compile Ruby code into ISeq cache, breaks coverage reporting.
  # all those other options
)
```

## Troubleshooting

The **most common problem is that simplecov isn't required and started before everything else**. In order to track coverage for your whole application **simplecov needs to be the first one** so that it (and the underlying coverage library) can subsequently track loaded files and their usage.

If you are missing coverage for some code a simple trick is to put a puts statement in there and right after `SimpleCov.start` so you can see if the file really was loaded after simplecov was started.

```ruby
# my_code.rb
class MyCode

  puts "MyCode is being loaded!"

  def my_method
    # ...
  end
end

# spec_helper.rb/rails_helper.rb/test_helper.rb/.simplecov whatever

SimpleCov.start
puts "SimpleCov started successfully!"
```

Now when you run your test suite and you see:

```
SimpleCov started successfully!
MyCode is being loaded!
```

then it's good otherwise you likely have a problem :)

## Contributing

See the [contributing guide](https://github.com/colszowka/simplecov/blob/master/CONTRIBUTING.md).

## Kudos

Thanks to Aaron Patterson for the original idea for this!

## Copyright

Copyright (c) 2010-2017 Christoph Olszowka. See MIT-LICENSE for details.
