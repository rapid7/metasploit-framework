# -*- encoding: utf-8 -*-
# stub: erubis 2.7.0 ruby lib

Gem::Specification.new do |s|
  s.name = "erubis".freeze
  s.version = "2.7.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["makoto kuwata".freeze]
  s.date = "2011-04-02"
  s.description = "  Erubis is an implementation of eRuby and has the following features:\n\n  * Very fast, almost three times faster than ERB and about 10% faster than eruby.\n  * Multi-language support (Ruby/PHP/C/Java/Scheme/Perl/Javascript)\n  * Auto escaping support\n  * Auto trimming spaces around '<% %>'\n  * Embedded pattern changeable (default '<% %>')\n  * Enable to handle Processing Instructions (PI) as embedded pattern (ex. '<?rb ... ?>')\n  * Context object available and easy to combine eRuby template with YAML datafile\n  * Print statement available\n  * Easy to extend and customize in subclass\n  * Ruby on Rails support\n".freeze
  s.email = "kwa(at)kuwata-lab.com".freeze
  s.executables = ["erubis".freeze]
  s.files = ["bin/erubis".freeze]
  s.homepage = "http://www.kuwata-lab.com/erubis/".freeze
  s.rubyforge_project = "erubis".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "a fast and extensible eRuby implementation which supports multi-language".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version
end
