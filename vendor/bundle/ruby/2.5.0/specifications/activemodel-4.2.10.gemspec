# -*- encoding: utf-8 -*-
# stub: activemodel 4.2.10 ruby lib

Gem::Specification.new do |s|
  s.name = "activemodel".freeze
  s.version = "4.2.10"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["David Heinemeier Hansson".freeze]
  s.date = "2017-09-27"
  s.description = "A toolkit for building modeling frameworks like Active Record. Rich support for attributes, callbacks, validations, serialization, internationalization, and testing.".freeze
  s.email = "david@loudthinking.com".freeze
  s.homepage = "http://www.rubyonrails.org".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9.3".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "A toolkit for building modeling frameworks (part of Rails).".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activesupport>.freeze, ["= 4.2.10"])
      s.add_runtime_dependency(%q<builder>.freeze, ["~> 3.1"])
    else
      s.add_dependency(%q<activesupport>.freeze, ["= 4.2.10"])
      s.add_dependency(%q<builder>.freeze, ["~> 3.1"])
    end
  else
    s.add_dependency(%q<activesupport>.freeze, ["= 4.2.10"])
    s.add_dependency(%q<builder>.freeze, ["~> 3.1"])
  end
end
