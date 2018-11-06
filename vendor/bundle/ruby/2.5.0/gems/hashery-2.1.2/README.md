# Hashery

[![Gem Version](http://img.shields.io/gem/v/hashery.svg?style=flat)](http://rubygems.org/gem/hashery)
[![Build Status](http://img.shields.io/travis/rubyworks/hashery.svg?style=flat)](http://travis-ci.org/rubyworks/hashery)
[![Fork Me](http://img.shields.io/badge/scm-github-blue.svg?style=flat)](http://github.com/rubyworks/hashery)
[![Report Issue](http://img.shields.io/github/issues/rubyworks/hashery.svg?style=flat)](http://github.com/rubyworks/hashery/issues)
[![Gittip](http://img.shields.io/badge/gittip-$1/wk-green.svg?style=flat)](https://www.gittip.com/rubyworksorg/)

[Homepage](http://rubyworks.github.com/hashery) &middot;
[Development](http://github.com/rubyworks/hashery) &middot;
[Report Issue](http://github.com/rubyworks/hashery/issues) &middot;
[Chat](https://kiwiirc.com/client/irc.freenode.net/?nick=user1|?#rubyworks)


## Description

Among Ruby Facets most common additions were an assortment
of Hash-like classes. To better support this collection
of libraries it was deemed prudent to create a new project
specifically for them. Hence the *Facets Hashery*.

Included in this collection are the widely used OrderedHash, 
the related but more featured Dictionary class, a number
of _open_ classes similar to the standard OpenStruct, 
some variations of the standard Hash class and a few
other yummy morsels.


## Usage

For instruction on usage, please see the individual library files
included in this collection and read the demo documents which give
examples of almost all features.


### Core Extensions

Hashery adds four core extensions of Ruby's Hash class: `#retrieve`,
`#rekey`, `#rekey!` and `Hash.create`. The first is simply an alias
for `#[]`. The later two have proven too useful over the years to
omit. And the last is a convenience class method for populating
a new hash with another hash upon initialization. All of these are
sorely missing for Ruby itself, which is why they are provided here.


## Installation

To install with RubyGems simply open a console and type:

    $ sudo gem install hashery

Or add it as a dependency to your project's Gemfile:

    gem "hashery"

Tarball packages are available for manual site installations
via [Ruby Setup](http://rubyworks.github.com/setup).


## Authors

Developers who have contributed code to the project include:

* Kirk Haines
* Joshua Hull
* Robert Klemme
* Jan Molic
* George Moschovitis
* Jeena Paradies
* Erik Veenstra


## Contributing

Don't be a lump on a log. See an issue? Have a suggestion? Want to help?
Well *git* in there!

### Communicating

The project is hosted on Github so the easiest means of communication 
is via the [Issues](http://github.com/rubyworks/hashery/issues) page.
For more direct communication you can try the **#rubyworks** IRC channel
on **irc.freenode.net**.

&nbsp; &nbsp; [![IRC](https://kiwiirc.com/buttons/irc.freenode.net/rubyworks.png)](https://kiwiirc.com/client/irc.freenode.net/?nick=user1|?#rubyworks)

### Testing

Hashery uses [QED](http://rubyworks.github.com/qed) and
[Lemon](http://rubyworks.github.com/lemon) test frameworks.
The QED framework to create well tested high-level documentation.
Run the QED specs via:

    $ qed -Ilib demo/

Lemon is used to create low-level unit tests. Run these via the Rubytest:

    $ rubytest -Ilib -Itest test/

### Patches

Hashery's repository is hosted on [GitHub](http://github.com/rubyworks/hashery).
If you'd like to offer up a fix or feature, fork the repo and submit a pull
request (preferably in a topic branch). I assume you have heard
all the talk about proper [practices](https://github.com/rubyworks/rubyworks.github.com/wiki/GitHub-Best-Pactices),
so I won't bug you with it yet again.

### Donations

Yes, we FOSS programmers need to eat too! ;-) No seriously, any help you can
offer goes a long way toward continued development of Rubyworks projects,
including Hashery. Hop over to our [Gittips](https://www.gittip.com/rubyworksorg/)
page, or see the upper right-hand corner on the [Rubyworks](http://rubyworks.github.com) homepage.
Thanks!


## Copyrights

Copyright (c) 2010 Rubyworks

Licensed under the *BSD-2-Clause* license.

See LICENSE.txt file for further details.

Some libraries included in the Hashery have special copyrights
attributing specific authors. Please see each library script for
specifics and the NOTICE.txt file for an overview.

