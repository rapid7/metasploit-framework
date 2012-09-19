# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rack-test"
  s.version = "0.6.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Bryan Helmkamp"]
  s.date = "2011-07-26"
  s.description = "Rack::Test is a small, simple testing API for Rack apps. It can be used on its\nown or as a reusable starting point for Web frameworks and testing libraries\nto build on. Most of its initial functionality is an extraction of Merb 1.0's\nrequest helpers feature."
  s.email = "bryan@brynary.com"
  s.extra_rdoc_files = ["README.rdoc", "MIT-LICENSE.txt"]
  s.files = ["README.rdoc", "MIT-LICENSE.txt"]
  s.homepage = "http://github.com/brynary/rack-test"
  s.require_paths = ["lib"]
  s.rubyforge_project = "rack-test"
  s.rubygems_version = "1.8.21"
  s.summary = "Simple testing API built on Rack"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rack>, [">= 1.0"])
    else
      s.add_dependency(%q<rack>, [">= 1.0"])
    end
  else
    s.add_dependency(%q<rack>, [">= 1.0"])
  end
end
