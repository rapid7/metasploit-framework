# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "treetop"
  s.version = "1.4.10"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Nathan Sobo"]
  s.autorequire = "treetop"
  s.date = "2011-07-27"
  s.email = "cliffordheath@gmail.com"
  s.executables = ["tt"]
  s.extra_rdoc_files = ["LICENSE", "README.md"]
  s.files = ["bin/tt", "LICENSE", "README.md"]
  s.homepage = "http://functionalform.blogspot.com"
  s.licenses = ["MIT"]
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "A Ruby-based text parsing and interpretation DSL"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<polyglot>, [">= 0"])
      s.add_development_dependency(%q<jeweler>, [">= 0"])
      s.add_development_dependency(%q<activesupport>, [">= 0"])
      s.add_development_dependency(%q<i18n>, ["~> 0.5.0"])
      s.add_development_dependency(%q<rr>, ["~> 0.10.2"])
      s.add_development_dependency(%q<rspec>, [">= 2.0.0"])
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_runtime_dependency(%q<polyglot>, [">= 0.3.1"])
    else
      s.add_dependency(%q<polyglot>, [">= 0"])
      s.add_dependency(%q<jeweler>, [">= 0"])
      s.add_dependency(%q<activesupport>, [">= 0"])
      s.add_dependency(%q<i18n>, ["~> 0.5.0"])
      s.add_dependency(%q<rr>, ["~> 0.10.2"])
      s.add_dependency(%q<rspec>, [">= 2.0.0"])
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<polyglot>, [">= 0.3.1"])
    end
  else
    s.add_dependency(%q<polyglot>, [">= 0"])
    s.add_dependency(%q<jeweler>, [">= 0"])
    s.add_dependency(%q<activesupport>, [">= 0"])
    s.add_dependency(%q<i18n>, ["~> 0.5.0"])
    s.add_dependency(%q<rr>, ["~> 0.10.2"])
    s.add_dependency(%q<rspec>, [">= 2.0.0"])
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<polyglot>, [">= 0.3.1"])
  end
end
