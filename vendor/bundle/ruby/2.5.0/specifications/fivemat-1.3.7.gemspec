# -*- encoding: utf-8 -*-
# stub: fivemat 1.3.7 ruby lib

Gem::Specification.new do |s|
  s.name = "fivemat".freeze
  s.version = "1.3.7"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Tim Pope".freeze]
  s.date = "2018-07-23"
  s.description = "MiniTest/RSpec/Cucumber formatter that gives each test file its own line of dots".freeze
  s.email = ["code@tpope.net".freeze]
  s.homepage = "https://github.com/tpope/fivemat".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Why settle for a test output format when you could have a test output fivemat?".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
    else
      s.add_dependency(%q<rake>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<rake>.freeze, [">= 0"])
  end
end
