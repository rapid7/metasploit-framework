= README

release::	2.7.0
copyright::	copyright(c) 2006-2011 kuwata-lab.com all rights reserved.



== About Erubis

Erubis is an implementation of eRuby. It has the following features.
* Very fast, almost three times faster than ERB and even 10% faster than eruby
* Multi-language support (Ruby/PHP/C/Java/Scheme/Perl/Javascript)
* Auto escaping support
* Auto trimming spaces around '<% %>'
* Embedded pattern changeable (default '<% %>')
* Enable to handle Processing Instructions (PI) as embedded pattern (ex. '<?rb ... ?>')
* Context object available and easy to combine eRuby template with YAML datafile
* Print statement available
* Easy to extend and customize in subclass
* Ruby on Rails support

Erubis is implemented in pure Ruby.  It requires Ruby 1.8 or higher.
Erubis now supports Ruby 1.9.

See doc/users-guide.html for details.



== Installation

* If you have installed RubyGems, just type <tt>gem install erubis</tt>.

    $ sudo gem install erubis

* Else install abstract[http://rubyforge.org/projects/abstract/] at first,
  and download erubis_X.X.X.tar.bz2 and install it by setup.rb.

    $ tar xjf abstract_X.X.X.tar.bz2
    $ cd abstract_X.X.X/
    $ sudo ruby setup.rb
    $ cd ..
    $ tar xjf erubis_X.X.X.tar.bz2
    $ cd erubis_X.X.X/
    $ sudo ruby setup.rb

* (Optional) It is able to merge 'lib/**/*.rb' into 'bin/erubis' by
  'contrib/inline-require' script.

    $ tar xjf erubis_X.X.X.tar.bz2
    $ cd erubis_X.X.X/
    $ cp /tmp/abstract_X.X.X/lib/abstract.rb lib
    $ unset RUBYLIB
    $ contrib/inline-require -I lib bin/erubis > contrib/erubis



== Ruby on Rails Support

Erubis supports Ruby on Rails.
All you have to do is to add the following code into your 'config/environment.rb'
and restart web server.

     require 'erubis/helpers/rails_helper'
     #Erubis::Helpers::RailsHelper.engine_class = Erubis::Eruby
     #Erubis::Helpers::RailsHelper.init_properties = {}
     #Erubis::Helpers::RailsHelper.show_src = nil

If Erubis::Helpers::RailsHelper.show_src is ture, Erubis prints converted Ruby code
into log file ('log/development.log' or so).  It is useful for debug.



== Exploring Guide

If you are exploring Eruby, see the following class at first.
* Erubis::TinyEruby (erubis/tiny.rb) --
  the most simple eRuby implementation.
* Erubis::Engine (erubis/engine.rb) --
  base class of Eruby, Ephp, Ejava, and so on.
* Erubis::Eruby (erubis/engine/eruby.rb) --
  engine class for eRuby.
* Erubis::Converter (erubis/converter.rb) --
  convert eRuby script into Ruby code.



== Benchmark

'benchmark/erubybenchmark.rb' is a benchmark script of Erubis.
Try 'ruby erubybenchmark.rb' in benchmark directory.



== License

MIT License



== Author

makoto kuwata <kwa(at)kuwata-lab.com>
