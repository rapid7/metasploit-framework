# -*- encoding: utf-8 -*-
# stub: rack-test 0.6.3 ruby lib

Gem::Specification.new do |s|
  s.name = "rack-test".freeze
  s.version = "0.6.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Bryan Helmkamp".freeze]
  s.date = "2015-01-09"
  s.description = "Rack::Test is a small, simple testing API for Rack apps. It can be used on its\nown or as a reusable starting point for Web frameworks and testing libraries\nto build on. Most of its initial functionality is an extraction of Merb 1.0's\nrequest helpers feature.".freeze
  s.email = "bryan@brynary.com".freeze
  s.extra_rdoc_files = ["README.rdoc".freeze, "MIT-LICENSE.txt".freeze]
  s.files = ["MIT-LICENSE.txt".freeze, "README.rdoc".freeze]
  s.homepage = "http://github.com/brynary/rack-test".freeze
  s.rubyforge_project = "rack-test".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Simple testing API built on Rack".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rack>.freeze, [">= 1.0"])
    else
      s.add_dependency(%q<rack>.freeze, [">= 1.0"])
    end
  else
    s.add_dependency(%q<rack>.freeze, [">= 1.0"])
  end
end
