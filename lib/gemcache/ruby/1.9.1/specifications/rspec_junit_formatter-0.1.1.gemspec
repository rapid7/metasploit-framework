# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rspec_junit_formatter"
  s.version = "0.1.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.6") if s.respond_to? :required_rubygems_version=
  s.authors = ["Samuel Cochran"]
  s.date = "2011-10-19"
  s.description = "RSpec results that Hudson can read."
  s.email = ["sj26@sj26.com"]
  s.homepage = "http://github.com/sj26/rspec_junit_formatter"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "RSpec JUnit XML formatter"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rspec>, ["~> 2.0"])
      s.add_runtime_dependency(%q<builder>, [">= 0"])
    else
      s.add_dependency(%q<rspec>, ["~> 2.0"])
      s.add_dependency(%q<builder>, [">= 0"])
    end
  else
    s.add_dependency(%q<rspec>, ["~> 2.0"])
    s.add_dependency(%q<builder>, [">= 0"])
  end
end
