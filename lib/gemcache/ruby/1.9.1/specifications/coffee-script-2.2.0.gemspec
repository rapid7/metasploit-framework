# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "coffee-script"
  s.version = "2.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Jeremy Ashkenas", "Joshua Peek", "Sam Stephenson"]
  s.date = "2010-03-11"
  s.description = "    Ruby CoffeeScript is a bridge to the JS CoffeeScript compiler.\n"
  s.email = "josh@joshpeek.com"
  s.homepage = "http://github.com/josh/ruby-coffee-script"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "Ruby CoffeeScript Compiler"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<coffee-script-source>, [">= 0"])
      s.add_runtime_dependency(%q<execjs>, [">= 0"])
    else
      s.add_dependency(%q<coffee-script-source>, [">= 0"])
      s.add_dependency(%q<execjs>, [">= 0"])
    end
  else
    s.add_dependency(%q<coffee-script-source>, [">= 0"])
    s.add_dependency(%q<execjs>, [">= 0"])
  end
end
