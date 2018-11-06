# -*- encoding: utf-8 -*-
# stub: sshkey 1.9.0 ruby lib

Gem::Specification.new do |s|
  s.name = "sshkey".freeze
  s.version = "1.9.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["James Miller".freeze]
  s.date = "2017-01-25"
  s.description = "Generate private/public SSH keypairs using pure Ruby".freeze
  s.email = ["bensie@gmail.com".freeze]
  s.homepage = "https://github.com/bensie/sshkey".freeze
  s.licenses = ["MIT".freeze]
  s.rubyforge_project = "sshkey".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "SSH private/public key generator in Ruby".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<test-unit>.freeze, [">= 0"])
    else
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<test-unit>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<test-unit>.freeze, [">= 0"])
  end
end
