# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "i18n"
  s.version = "0.6.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.5") if s.respond_to? :required_rubygems_version=
  s.authors = ["Sven Fuchs", "Joshua Harvey", "Matt Aimonetti", "Stephan Soller", "Saimon Moore"]
  s.date = "2012-08-31"
  s.description = "New wave Internationalization support for Ruby."
  s.email = "rails-i18n@googlegroups.com"
  s.homepage = "http://github.com/svenfuchs/i18n"
  s.require_paths = ["lib"]
  s.rubyforge_project = "[none]"
  s.rubygems_version = "1.8.24"
  s.summary = "New wave Internationalization support for Ruby"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<activesupport>, ["~> 3.0.0"])
      s.add_development_dependency(%q<sqlite3>, [">= 0"])
      s.add_development_dependency(%q<mocha>, [">= 0"])
      s.add_development_dependency(%q<test_declarative>, [">= 0"])
    else
      s.add_dependency(%q<activesupport>, ["~> 3.0.0"])
      s.add_dependency(%q<sqlite3>, [">= 0"])
      s.add_dependency(%q<mocha>, [">= 0"])
      s.add_dependency(%q<test_declarative>, [">= 0"])
    end
  else
    s.add_dependency(%q<activesupport>, ["~> 3.0.0"])
    s.add_dependency(%q<sqlite3>, [">= 0"])
    s.add_dependency(%q<mocha>, [">= 0"])
    s.add_dependency(%q<test_declarative>, [">= 0"])
  end
end
