# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rails-dev-tweaks"
  s.version = "0.6.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Wavii, Inc."]
  s.date = "2012-02-06"
  s.description = "A collection of tweaks to improve your Rails (3.1+) development experience."
  s.email = ["info@wavii.com"]
  s.homepage = "http://wavii.com/"
  s.require_paths = ["lib"]
  s.rubyforge_project = "rails-dev-tweaks"
  s.rubygems_version = "1.8.21"
  s.summary = "A collection of tweaks to improve your Rails (3.1+) development experience."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<railties>, ["~> 3.1"])
      s.add_runtime_dependency(%q<actionpack>, ["~> 3.1"])
    else
      s.add_dependency(%q<railties>, ["~> 3.1"])
      s.add_dependency(%q<actionpack>, ["~> 3.1"])
    end
  else
    s.add_dependency(%q<railties>, ["~> 3.1"])
    s.add_dependency(%q<actionpack>, ["~> 3.1"])
  end
end
