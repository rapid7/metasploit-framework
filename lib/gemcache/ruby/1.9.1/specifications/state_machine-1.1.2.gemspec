# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "state_machine"
  s.version = "1.1.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Aaron Pfeifer"]
  s.date = "2012-04-12"
  s.description = "Adds support for creating state machines for attributes on any Ruby class"
  s.email = "aaron@pluginaweek.org"
  s.extra_rdoc_files = ["README.md", "CHANGELOG.md", "LICENSE"]
  s.files = ["README.md", "CHANGELOG.md", "LICENSE"]
  s.homepage = "http://www.pluginaweek.org"
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "state_machine", "--main", "README.md"]
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "State machines for attributes"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_development_dependency(%q<simplecov>, [">= 0"])
      s.add_development_dependency(%q<appraisal>, ["~> 0.4.0"])
    else
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<simplecov>, [">= 0"])
      s.add_dependency(%q<appraisal>, ["~> 0.4.0"])
    end
  else
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<simplecov>, [">= 0"])
    s.add_dependency(%q<appraisal>, ["~> 0.4.0"])
  end
end
