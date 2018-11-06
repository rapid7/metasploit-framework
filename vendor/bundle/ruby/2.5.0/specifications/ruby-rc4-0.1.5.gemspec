# -*- encoding: utf-8 -*-
# stub: ruby-rc4 0.1.5 ruby lib

Gem::Specification.new do |s|
  s.name = "ruby-rc4".freeze
  s.version = "0.1.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Caige Nichols".freeze]
  s.date = "2012-01-25"
  s.email = "caigesn@gmail.com".freeze
  s.extra_rdoc_files = ["README.md".freeze]
  s.files = ["README.md".freeze]
  s.homepage = "http://www.caigenichols.com/".freeze
  s.rdoc_options = ["--main".freeze, "README.md".freeze]
  s.rubyforge_project = "ruby-rc4".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "RubyRC4 is a pure Ruby implementation of the RC4 algorithm.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>.freeze, [">= 0"])
    else
      s.add_dependency(%q<rspec>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<rspec>.freeze, [">= 0"])
  end
end
