# -*- encoding: utf-8 -*-
# stub: simplecov 0.16.1 ruby lib

Gem::Specification.new do |s|
  s.name = "simplecov".freeze
  s.version = "0.16.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Christoph Olszowka".freeze]
  s.date = "2018-03-16"
  s.description = "Code coverage for Ruby 1.9+ with a powerful configuration library and automatic merging of coverage across test suites".freeze
  s.email = ["christoph at olszowka de".freeze]
  s.homepage = "http://github.com/colszowka/simplecov".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Code coverage for Ruby 1.9+ with a powerful configuration library and automatic merging of coverage across test suites".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<json>.freeze, ["< 3", ">= 1.8"])
      s.add_runtime_dependency(%q<simplecov-html>.freeze, ["~> 0.10.0"])
      s.add_runtime_dependency(%q<docile>.freeze, ["~> 1.1"])
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.9"])
    else
      s.add_dependency(%q<json>.freeze, ["< 3", ">= 1.8"])
      s.add_dependency(%q<simplecov-html>.freeze, ["~> 0.10.0"])
      s.add_dependency(%q<docile>.freeze, ["~> 1.1"])
      s.add_dependency(%q<bundler>.freeze, ["~> 1.9"])
    end
  else
    s.add_dependency(%q<json>.freeze, ["< 3", ">= 1.8"])
    s.add_dependency(%q<simplecov-html>.freeze, ["~> 0.10.0"])
    s.add_dependency(%q<docile>.freeze, ["~> 1.1"])
    s.add_dependency(%q<bundler>.freeze, ["~> 1.9"])
  end
end
