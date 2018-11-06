# -*- encoding: utf-8 -*-
# stub: nexpose 7.2.1 ruby lib

Gem::Specification.new do |s|
  s.name = "nexpose".freeze
  s.version = "7.2.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["HD Moore".freeze, "Chris Lee".freeze, "Michael Daines".freeze, "Brandon Turner".freeze, "Gavin Schneider".freeze, "Scott Green".freeze]
  s.date = "2018-06-01"
  s.description = "This gem provides a Ruby API to the Nexpose vulnerability management product by Rapid7.".freeze
  s.email = ["hd_moore@rapid7.com".freeze, "christopher_lee@rapid7.com".freeze, "michael_daines@rapid7.com".freeze, "brandon_turner@rapid7.com".freeze, "gavin_schneider@rapid7.com".freeze, "scott_green@rapid7.com".freeze]
  s.extra_rdoc_files = ["README.markdown".freeze]
  s.files = ["README.markdown".freeze]
  s.homepage = "https://github.com/rapid7/nexpose-client".freeze
  s.licenses = ["BSD-3-Clause".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Ruby API for Rapid7 Nexpose".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.3"])
      s.add_development_dependency(%q<codeclimate-test-reporter>.freeze, ["~> 0.4.6"])
      s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.9.1"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, ["~> 3.2"])
      s.add_development_dependency(%q<rubocop>.freeze, [">= 0"])
      s.add_development_dependency(%q<webmock>.freeze, ["~> 1.20.4"])
      s.add_development_dependency(%q<vcr>.freeze, ["~> 2.9.3"])
      s.add_development_dependency(%q<github_changelog_generator>.freeze, [">= 0"])
      s.add_development_dependency(%q<pry>.freeze, ["= 0.9.12.6"])
    else
      s.add_dependency(%q<bundler>.freeze, ["~> 1.3"])
      s.add_dependency(%q<codeclimate-test-reporter>.freeze, ["~> 0.4.6"])
      s.add_dependency(%q<simplecov>.freeze, ["~> 0.9.1"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, ["~> 3.2"])
      s.add_dependency(%q<rubocop>.freeze, [">= 0"])
      s.add_dependency(%q<webmock>.freeze, ["~> 1.20.4"])
      s.add_dependency(%q<vcr>.freeze, ["~> 2.9.3"])
      s.add_dependency(%q<github_changelog_generator>.freeze, [">= 0"])
      s.add_dependency(%q<pry>.freeze, ["= 0.9.12.6"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.3"])
    s.add_dependency(%q<codeclimate-test-reporter>.freeze, ["~> 0.4.6"])
    s.add_dependency(%q<simplecov>.freeze, ["~> 0.9.1"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, ["~> 3.2"])
    s.add_dependency(%q<rubocop>.freeze, [">= 0"])
    s.add_dependency(%q<webmock>.freeze, ["~> 1.20.4"])
    s.add_dependency(%q<vcr>.freeze, ["~> 2.9.3"])
    s.add_dependency(%q<github_changelog_generator>.freeze, [">= 0"])
    s.add_dependency(%q<pry>.freeze, ["= 0.9.12.6"])
  end
end
