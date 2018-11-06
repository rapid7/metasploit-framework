# Description

The readline library provides a pure Ruby implementation of the GNU
readline C library, as well as the Readline extension that ships as part
of the standard library.

## Installation

    gem install rb-readline
  
Or in a `Gemfile`:
  
    gem 'rb-readline'

## Synopsis

```ruby
require 'readline'

loop do
  line = Readline::readline('> ')
  break if line.nil? || line == 'quit'
  Readline::HISTORY.push(line)
  puts "You typed: #{line}"
end
```

## Compatibility

rb-readline should work on all Unix-like systems and Windows. It is regularly
used with MRI 1.8/1.9 and Rubinius. JRuby is not supported and there are no
plans to support it in the future - it comes bundled with a Java implementation
of Readline.

## Motivation

First, building the GNU readline library on MS Windows with Visual C++ is
almost impossible. However, certain libraries depend on readline. By providing
a pure Ruby version we eliminate the entire compiler compatibility issue.

Second, even on distributions of Windows built with MinGW (that include
the readline library for Windows), the behavior was sometimes erratic and
would break.

Third, even on certain Unix distributions the GNU readline library is not
guaranteed to be installed. Providing a pure Ruby readline eliminates the
need to install a C library first. It's also one less link in the dependency
chain, meaning we don't need to worry about possible changes in the underlying
C library affecting our interface.

Fourth, by making the interface pure Ruby, we increase the likelihood of
receiving patches, feature requests, documentation updates, etc from the
community at large, since not everyone knows C.

Lastly, the Readline interface that ships as part of the standard library is
weak, and only provides a very limited subset of the actual GNU readline
library. By providing a pure Ruby implementation we allow 3rd party library
authors to write their own interface as they see fit.

## Tutorial

For an excellent tutorial on how to use Readline in practice, please see
Joseph Pecoraro's examples at http://bogojoker.com/readline/.

You can also take a look at Ruby 1.9 stdlib Readline documentation located
at http://rubydoc.info/stdlib/readline/1.9.2/frames

## Alternatives

See Rawline for a library that began life in pure Ruby and provides an
interface that's probably more comfortable to Ruby programmer. It has certain
features that Readline does not. In addition, it provides a Readline
compatibility mode.

## Authors

* Park Heesob (C translation, code donated as part of bounty)
* Daniel Berger (Documentation and testing)
* Luis Lavena
* Mark Somerville (Maintainer)
* Connor Atherton (Maintainer)
