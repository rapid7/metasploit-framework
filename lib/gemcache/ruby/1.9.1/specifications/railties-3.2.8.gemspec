# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "railties"
  s.version = "3.2.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["David Heinemeier Hansson"]
  s.date = "2012-08-09"
  s.description = "Rails internals: application bootup, plugins, generators, and rake tasks."
  s.email = "david@loudthinking.com"
  s.executables = ["rails"]
  s.files = ["bin/rails"]
  s.homepage = "http://www.rubyonrails.org"
  s.rdoc_options = ["--exclude", "."]
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubygems_version = "1.8.24"
  s.summary = "Tools for creating, working with, and running Rails applications."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rake>, [">= 0.8.7"])
      s.add_runtime_dependency(%q<rack-ssl>, ["~> 1.3.2"])
      s.add_runtime_dependency(%q<thor>, ["< 2.0", ">= 0.14.6"])
      s.add_runtime_dependency(%q<rdoc>, ["~> 3.4"])
      s.add_runtime_dependency(%q<activesupport>, ["= 3.2.8"])
      s.add_runtime_dependency(%q<actionpack>, ["= 3.2.8"])
    else
      s.add_dependency(%q<rake>, [">= 0.8.7"])
      s.add_dependency(%q<rack-ssl>, ["~> 1.3.2"])
      s.add_dependency(%q<thor>, ["< 2.0", ">= 0.14.6"])
      s.add_dependency(%q<rdoc>, ["~> 3.4"])
      s.add_dependency(%q<activesupport>, ["= 3.2.8"])
      s.add_dependency(%q<actionpack>, ["= 3.2.8"])
    end
  else
    s.add_dependency(%q<rake>, [">= 0.8.7"])
    s.add_dependency(%q<rack-ssl>, ["~> 1.3.2"])
    s.add_dependency(%q<thor>, ["< 2.0", ">= 0.14.6"])
    s.add_dependency(%q<rdoc>, ["~> 3.4"])
    s.add_dependency(%q<activesupport>, ["= 3.2.8"])
    s.add_dependency(%q<actionpack>, ["= 3.2.8"])
  end
end
