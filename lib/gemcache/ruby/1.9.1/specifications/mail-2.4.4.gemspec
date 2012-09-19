# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "mail"
  s.version = "2.4.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Mikel Lindsaar"]
  s.date = "2012-03-14"
  s.description = "A really Ruby Mail handler."
  s.email = "raasdnil@gmail.com"
  s.extra_rdoc_files = ["README.md", "CONTRIBUTING.md", "CHANGELOG.rdoc", "TODO.rdoc"]
  s.files = ["README.md", "CONTRIBUTING.md", "CHANGELOG.rdoc", "TODO.rdoc"]
  s.homepage = "http://github.com/mikel/mail"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "Mail provides a nice Ruby DSL for making, sending and reading emails."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<mime-types>, ["~> 1.16"])
      s.add_runtime_dependency(%q<treetop>, ["~> 1.4.8"])
      s.add_runtime_dependency(%q<i18n>, [">= 0.4.0"])
    else
      s.add_dependency(%q<mime-types>, ["~> 1.16"])
      s.add_dependency(%q<treetop>, ["~> 1.4.8"])
      s.add_dependency(%q<i18n>, [">= 0.4.0"])
    end
  else
    s.add_dependency(%q<mime-types>, ["~> 1.16"])
    s.add_dependency(%q<treetop>, ["~> 1.4.8"])
    s.add_dependency(%q<i18n>, [">= 0.4.0"])
  end
end
