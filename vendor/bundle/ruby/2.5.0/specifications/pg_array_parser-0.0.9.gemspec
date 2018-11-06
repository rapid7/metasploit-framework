# -*- encoding: utf-8 -*-
# stub: pg_array_parser 0.0.9 ruby lib
# stub: ext/pg_array_parser/extconf.rb

Gem::Specification.new do |s|
  s.name = "pg_array_parser".freeze
  s.version = "0.0.9"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Dan McClain".freeze]
  s.date = "2013-08-02"
  s.description = "Simple library to parse PostgreSQL arrays into a array of strings".freeze
  s.email = ["git@danmcclain.net".freeze]
  s.extensions = ["ext/pg_array_parser/extconf.rb".freeze]
  s.files = ["ext/pg_array_parser/extconf.rb".freeze]
  s.homepage = "https://github.com/dockyard/pg_array_parser".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Converts PostgreSQL array strings into arrays of strings".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>.freeze, ["~> 2.11.0"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 0.9.2.2"])
      s.add_development_dependency(%q<rake-compiler>.freeze, [">= 0"])
    else
      s.add_dependency(%q<rspec>.freeze, ["~> 2.11.0"])
      s.add_dependency(%q<rake>.freeze, ["~> 0.9.2.2"])
      s.add_dependency(%q<rake-compiler>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<rspec>.freeze, ["~> 2.11.0"])
    s.add_dependency(%q<rake>.freeze, ["~> 0.9.2.2"])
    s.add_dependency(%q<rake-compiler>.freeze, [">= 0"])
  end
end
