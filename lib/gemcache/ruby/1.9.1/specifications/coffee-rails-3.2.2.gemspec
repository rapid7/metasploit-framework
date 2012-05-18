# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "coffee-rails"
  s.version = "3.2.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Santiago Pastorino"]
  s.date = "2012-01-26"
  s.description = "Coffee Script adapter for the Rails asset pipeline."
  s.email = ["santiago@wyeworks.com"]
  s.homepage = ""
  s.require_paths = ["lib"]
  s.rubyforge_project = "coffee-rails"
  s.rubygems_version = "1.8.21"
  s.summary = "Coffee Script adapter for the Rails asset pipeline."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<coffee-script>, [">= 2.2.0"])
      s.add_runtime_dependency(%q<railties>, ["~> 3.2.0"])
    else
      s.add_dependency(%q<coffee-script>, [">= 2.2.0"])
      s.add_dependency(%q<railties>, ["~> 3.2.0"])
    end
  else
    s.add_dependency(%q<coffee-script>, [">= 2.2.0"])
    s.add_dependency(%q<railties>, ["~> 3.2.0"])
  end
end
