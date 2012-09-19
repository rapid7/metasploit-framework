# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rspec-expectations"
  s.version = "2.8.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Steven Baker", "David Chelimsky"]
  s.date = "2012-01-05"
  s.description = "rspec expectations (should[_not] and matchers)"
  s.email = "rspec-users@rubyforge.org"
  s.extra_rdoc_files = ["README.md", "License.txt"]
  s.files = ["README.md", "License.txt"]
  s.homepage = "http://github.com/rspec/rspec-expectations"
  s.licenses = ["MIT"]
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "rspec"
  s.rubygems_version = "1.8.21"
  s.summary = "rspec-expectations-2.8.0"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<diff-lcs>, ["~> 1.1.2"])
    else
      s.add_dependency(%q<diff-lcs>, ["~> 1.1.2"])
    end
  else
    s.add_dependency(%q<diff-lcs>, ["~> 1.1.2"])
  end
end
