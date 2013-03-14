# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "simplecov"
  s.version = "0.5.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Christoph Olszowka"]
  s.date = "2011-10-11"
  s.description = "Code coverage for Ruby 1.9 with a powerful configuration library and automatic merging of coverage across test suites"
  s.email = ["christoph at olszowka de"]
  s.homepage = "http://github.com/colszowka/simplecov"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "Code coverage for Ruby 1.9 with a powerful configuration library and automatic merging of coverage across test suites"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<multi_json>, ["~> 1.0.3"])
      s.add_runtime_dependency(%q<simplecov-html>, ["~> 0.5.3"])
      s.add_development_dependency(%q<aruba>, ["~> 0.4"])
      s.add_development_dependency(%q<capybara>, ["~> 1.0"])
      s.add_development_dependency(%q<cucumber>, ["~> 1.0.5"])
      s.add_development_dependency(%q<rake>, ["~> 0.8"])
      s.add_development_dependency(%q<rspec>, ["~> 2.6"])
      s.add_development_dependency(%q<shoulda>, ["~> 2.10"])
    else
      s.add_dependency(%q<multi_json>, ["~> 1.0.3"])
      s.add_dependency(%q<simplecov-html>, ["~> 0.5.3"])
      s.add_dependency(%q<aruba>, ["~> 0.4"])
      s.add_dependency(%q<capybara>, ["~> 1.0"])
      s.add_dependency(%q<cucumber>, ["~> 1.0.5"])
      s.add_dependency(%q<rake>, ["~> 0.8"])
      s.add_dependency(%q<rspec>, ["~> 2.6"])
      s.add_dependency(%q<shoulda>, ["~> 2.10"])
    end
  else
    s.add_dependency(%q<multi_json>, ["~> 1.0.3"])
    s.add_dependency(%q<simplecov-html>, ["~> 0.5.3"])
    s.add_dependency(%q<aruba>, ["~> 0.4"])
    s.add_dependency(%q<capybara>, ["~> 1.0"])
    s.add_dependency(%q<cucumber>, ["~> 1.0.5"])
    s.add_dependency(%q<rake>, ["~> 0.8"])
    s.add_dependency(%q<rspec>, ["~> 2.6"])
    s.add_dependency(%q<shoulda>, ["~> 2.10"])
  end
end
