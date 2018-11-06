# -*- encoding: utf-8 -*-
# stub: rubyntlm 0.6.2 ruby lib

Gem::Specification.new do |s|
  s.name = "rubyntlm".freeze
  s.version = "0.6.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Kohei Kajimoto".freeze, "Paul Morton".freeze]
  s.date = "2017-04-24"
  s.description = "Ruby/NTLM provides message creator and parser for the NTLM authentication.".freeze
  s.email = ["koheik@gmail.com".freeze, "paul.e.morton@gmail.com".freeze]
  s.homepage = "https://github.com/winrb/rubyntlm".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Ruby/NTLM library.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<github_changelog_generator>.freeze, ["= 1.14.3"])
      s.add_development_dependency(%q<pry>.freeze, [">= 0"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, [">= 2.11"])
      s.add_development_dependency(%q<simplecov>.freeze, [">= 0"])
    else
      s.add_dependency(%q<github_changelog_generator>.freeze, ["= 1.14.3"])
      s.add_dependency(%q<pry>.freeze, [">= 0"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, [">= 2.11"])
      s.add_dependency(%q<simplecov>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<github_changelog_generator>.freeze, ["= 1.14.3"])
    s.add_dependency(%q<pry>.freeze, [">= 0"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, [">= 2.11"])
    s.add_dependency(%q<simplecov>.freeze, [">= 0"])
  end
end
