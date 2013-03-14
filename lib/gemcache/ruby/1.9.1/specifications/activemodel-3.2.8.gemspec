# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "activemodel"
  s.version = "3.2.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["David Heinemeier Hansson"]
  s.date = "2012-08-09"
  s.description = "A toolkit for building modeling frameworks like Active Record and Active Resource. Rich support for attributes, callbacks, validations, observers, serialization, internationalization, and testing."
  s.email = "david@loudthinking.com"
  s.homepage = "http://www.rubyonrails.org"
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubygems_version = "1.8.24"
  s.summary = "A toolkit for building modeling frameworks (part of Rails)."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activesupport>, ["= 3.2.8"])
      s.add_runtime_dependency(%q<builder>, ["~> 3.0.0"])
    else
      s.add_dependency(%q<activesupport>, ["= 3.2.8"])
      s.add_dependency(%q<builder>, ["~> 3.0.0"])
    end
  else
    s.add_dependency(%q<activesupport>, ["= 3.2.8"])
    s.add_dependency(%q<builder>, ["~> 3.0.0"])
  end
end
