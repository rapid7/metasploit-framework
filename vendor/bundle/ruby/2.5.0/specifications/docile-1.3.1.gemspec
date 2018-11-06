# -*- encoding: utf-8 -*-
# stub: docile 1.3.1 ruby lib

Gem::Specification.new do |s|
  s.name = "docile".freeze
  s.version = "1.3.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Marc Siegel".freeze]
  s.date = "2018-05-24"
  s.description = "Docile treats the methods of a given ruby object as a DSL (domain specific language) within a given block. \n\nKiller feature: you can also reference methods, instance variables, and local variables from the original (non-DSL) context within the block. \n\nDocile releases follow Semantic Versioning as defined at semver.org.".freeze
  s.email = "marc@usainnov.com".freeze
  s.homepage = "https://ms-ati.github.io/docile/".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Docile keeps your Ruby DSLs tame and well-behaved.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, ["< 11.0"])
      s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0"])
      s.add_development_dependency(%q<yard>.freeze, [">= 0"])
      s.add_development_dependency(%q<redcarpet>.freeze, [">= 0"])
      s.add_development_dependency(%q<github-markup>.freeze, [">= 0"])
    else
      s.add_dependency(%q<rake>.freeze, ["< 11.0"])
      s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
      s.add_dependency(%q<yard>.freeze, [">= 0"])
      s.add_dependency(%q<redcarpet>.freeze, [">= 0"])
      s.add_dependency(%q<github-markup>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<rake>.freeze, ["< 11.0"])
    s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
    s.add_dependency(%q<yard>.freeze, [">= 0"])
    s.add_dependency(%q<redcarpet>.freeze, [">= 0"])
    s.add_dependency(%q<github-markup>.freeze, [">= 0"])
  end
end
