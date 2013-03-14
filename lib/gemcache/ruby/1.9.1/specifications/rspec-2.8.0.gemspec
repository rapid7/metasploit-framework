# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rspec"
  s.version = "2.8.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Steven Baker", "David Chelimsky"]
  s.date = "2012-01-05"
  s.description = "BDD for Ruby"
  s.email = "rspec-users@rubyforge.org"
  s.extra_rdoc_files = ["README.markdown"]
  s.files = ["README.markdown"]
  s.homepage = "http://github.com/rspec"
  s.licenses = ["MIT"]
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "rspec"
  s.rubygems_version = "1.8.21"
  s.summary = "rspec-2.8.0"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rspec-core>, ["~> 2.8.0"])
      s.add_runtime_dependency(%q<rspec-expectations>, ["~> 2.8.0"])
      s.add_runtime_dependency(%q<rspec-mocks>, ["~> 2.8.0"])
    else
      s.add_dependency(%q<rspec-core>, ["~> 2.8.0"])
      s.add_dependency(%q<rspec-expectations>, ["~> 2.8.0"])
      s.add_dependency(%q<rspec-mocks>, ["~> 2.8.0"])
    end
  else
    s.add_dependency(%q<rspec-core>, ["~> 2.8.0"])
    s.add_dependency(%q<rspec-expectations>, ["~> 2.8.0"])
    s.add_dependency(%q<rspec-mocks>, ["~> 2.8.0"])
  end
end
