# -*- encoding: utf-8 -*-
# stub: rb-readline 0.5.5 ruby lib

Gem::Specification.new do |s|
  s.name = "rb-readline".freeze
  s.version = "0.5.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.5".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Park Heesob".freeze, "Daniel Berger".freeze, "Luis Lavena".freeze, "Connor Atherton".freeze]
  s.date = "2017-07-29"
  s.description = "The readline library provides a pure Ruby implementation of the GNU readline C library, as well as the Readline extension that ships as part of the standard library.".freeze
  s.email = ["phasis@gmail.com".freeze, "djberg96@gmail.com".freeze, "luislavena@gmail.com".freeze, "c.liam.atherton@gmail.com".freeze]
  s.extra_rdoc_files = ["README.md".freeze, "LICENSE".freeze, "CHANGES".freeze]
  s.files = ["CHANGES".freeze, "LICENSE".freeze, "README.md".freeze]
  s.homepage = "http://github.com/ConnorAtherton/rb-readline".freeze
  s.licenses = ["BSD".freeze]
  s.rdoc_options = ["--main".freeze, "README.md".freeze, "--title".freeze, "Rb-Readline - Documentation".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.6".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Pure-Ruby Readline Implementation".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<minitest>.freeze, ["~> 5.2"])
    else
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<minitest>.freeze, ["~> 5.2"])
    end
  else
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<minitest>.freeze, ["~> 5.2"])
  end
end
