# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "compass-rails"
  s.version = "1.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Scott Davis", "Chris Eppstein"]
  s.date = "2012-03-19"
  s.description = "Integrate Compass into Rails 2.3 and up."
  s.email = ["jetviper21@gmail.com", "chris@eppsteins.net"]
  s.homepage = "https://github.com/Compass/compass-rails"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "Integrate Compass into Rails 2.3 and up."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<compass>, ["~> 0.12.0"])
    else
      s.add_dependency(%q<compass>, ["~> 0.12.0"])
    end
  else
    s.add_dependency(%q<compass>, ["~> 0.12.0"])
  end
end
