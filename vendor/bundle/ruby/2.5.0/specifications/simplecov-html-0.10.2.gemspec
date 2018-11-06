# -*- encoding: utf-8 -*-
# stub: simplecov-html 0.10.2 ruby lib

Gem::Specification.new do |s|
  s.name = "simplecov-html".freeze
  s.version = "0.10.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Christoph Olszowka".freeze]
  s.date = "2017-08-14"
  s.description = "Default HTML formatter for SimpleCov code coverage tool for ruby 1.9+".freeze
  s.email = ["christoph at olszowka de".freeze]
  s.homepage = "https://github.com/colszowka/simplecov-html".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Default HTML formatter for SimpleCov code coverage tool for ruby 1.9+".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.9"])
    else
      s.add_dependency(%q<bundler>.freeze, ["~> 1.9"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.9"])
  end
end
