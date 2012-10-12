# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "activesupport"
  s.version = "3.2.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["David Heinemeier Hansson"]
  s.date = "2012-08-09"
  s.description = "A toolkit of support libraries and Ruby core extensions extracted from the Rails framework. Rich support for multibyte strings, internationalization, time zones, and testing."
  s.email = "david@loudthinking.com"
  s.homepage = "http://www.rubyonrails.org"
  s.rdoc_options = ["--encoding", "UTF-8"]
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubygems_version = "1.8.24"
  s.summary = "A toolkit of support libraries and Ruby core extensions extracted from the Rails framework."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<i18n>, ["~> 0.6"])
      s.add_runtime_dependency(%q<multi_json>, ["~> 1.0"])
    else
      s.add_dependency(%q<i18n>, ["~> 0.6"])
      s.add_dependency(%q<multi_json>, ["~> 1.0"])
    end
  else
    s.add_dependency(%q<i18n>, ["~> 0.6"])
    s.add_dependency(%q<multi_json>, ["~> 1.0"])
  end
end
