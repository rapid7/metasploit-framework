# MultiJSON [![Build Status](https://secure.travis-ci.org/intridea/multi_json.png?branch=master)][travis] [![Dependency Status](https://gemnasium.com/intridea/multi_json.png?travis)][gemnasium]

[travis]: http://travis-ci.org/intridea/multi_json
[gemnasium]: https://gemnasium.com/intridea/multi_json

Lots of Ruby libraries parse JSON and everyone has their favorite JSON coder.
Instead of choosing a single JSON coder and forcing users of your library to be
stuck with it, you can use MultiJSON instead, which will simply choose the
fastest available JSON coder. Here's how to use it:

    require 'multi_json'

    MultiJson.decode('{"abc":"def"}') #=> {"abc" => "def"}
    MultiJson.decode('{"abc":"def"}', :symbolize_keys => true) #=> {:abc => "def"}
    MultiJson.encode({:abc => 'def'}) # convert Ruby back to JSON
    MultiJson.encode({:abc => 'def'}, :pretty => true) # encoded in a pretty form (if supported by the coder)

The `engine` setter takes either a symbol or a class (to allow for custom JSON
parsers) that responds to both `.decode` and `.encode` at the class level.

MultiJSON tries to have intelligent defaulting. That is, if you have any of the
supported engines already loaded, it will utilize them before attempting to
load any. When loading, libraries are ordered by speed. First Oj, then Yajl,
then the JSON gem, then JSON pure. If no other JSON library is available,
MultiJSON falls back to [OkJson][], a simple, vendorable JSON parser.

[okjson]: https://github.com/kr/okjson

## Supported JSON Engines

* [Oj](https://github.com/ohler55/oj) Optimized JSON by Peter Ohler
* [Yajl](https://github.com/brianmario/yajl-ruby) Yet Another JSON Library by Brian Lopez
* [JSON](https://github.com/flori/json) The default JSON gem with C-extensions (ships with Ruby 1.9)
* [JSON Pure](https://github.com/flori/json) A Ruby variant of the JSON gem
* [NSJSONSerialization](https://developer.apple.com/library/ios/#documentation/Foundation/Reference/NSJSONSerialization_Class/Reference/Reference.html) Wrapper for Apple's NSJSONSerialization in the Cocoa Framework (MacRuby only)
* [OkJson][okjson] A simple, vendorable JSON parser

## <a name="contributing"></a>Contributing
In the spirit of [free software][free-sw], **everyone** is encouraged to help
improve this project.

[free-sw]: http://www.fsf.org/licensing/essays/free-sw.html

Here are some ways *you* can contribute:

* by using alpha, beta, and prerelease versions
* by reporting bugs
* by suggesting new features
* by writing or editing documentation
* by writing specifications
* by writing code (**no patch is too small**: fix typos, add comments, clean up
  inconsistent whitespace)
* by refactoring code
* by closing [issues][]
* by reviewing patches

[issues]: https://github.com/intridea/multi_json/issues

## <a name="issues"></a>Submitting an Issue
We use the [GitHub issue tracker][issues] to track bugs and features. Before
submitting a bug report or feature request, check to make sure it hasn't
already been submitted. You can indicate support for an existing issuse by
voting it up. When submitting a bug report, please include a [Gist][] that
includes a stack trace and any details that may be necessary to reproduce the
bug, including your gem version, Ruby version, and operating system. Ideally, a
bug report should include a pull request with failing specs.

[gist]: https://gist.github.com/

## <a name="pulls"></a>Submitting a Pull Request
1. Fork the project.
2. Create a topic branch.
3. Implement your feature or bug fix.
4. Add specs for your feature or bug fix.
5. Run `bundle exec rake spec`. If your changes are not 100% covered, go back
   to step 4.
6. Commit and push your changes.
7. Submit a pull request. Please do not include changes to the gemspec,
   version, or history file. (If you want to create your own version for some
   reason, please do so in a separate commit.)

## <a name="versions"></a>Supported Ruby Versions
This library aims to support and is [tested against][travis] the following Ruby
implementations:

* Ruby 1.8.7
* Ruby 1.9.2
* Ruby 1.9.3
* [JRuby][]
* [Rubinius][]
* [Ruby Enterprise Edition][ree]
* [MacRuby][] (not tested on Travis CI)

[jruby]: http://www.jruby.org/
[rubinius]: http://rubini.us/
[ree]: http://www.rubyenterpriseedition.com/
[macruby]: http://www.macruby.org/

If something doesn't work on one of these interpreters, it should be considered
a bug.

This library may inadvertently work (or seem to work) on other Ruby
implementations, however support will only be provided for the versions listed
above.

If you would like this library to support another Ruby version, you may
volunteer to be a maintainer. Being a maintainer entails making sure all tests
run and pass on that implementation. When something breaks on your
implementation, you will be personally responsible for providing patches in a
timely fashion. If critical issues for a particular implementation exist at the
time of a major release, support for that Ruby version may be dropped.

## <a name="copyright"></a>Copyright
Copyright (c) 2010 Michael Bleigh, Josh Kalderimis, Erik Michaels-Ober, and Intridea, Inc.
See [LICENSE][] for details.

[license]: https://github.com/intridea/multi_json/blob/master/LICENSE.md
