# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "simplecov-rcov"
  s.version = "0.2.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = ["Fernando Guillen http://fernandoguillen.info", "Wes Morgan http://github.com/cap10morgan", "Wandenberg Peixoto http://github.com/wandenberg"]
  s.date = "2011-02-09"
  s.description = "Rcov style formatter for SimpleCov"
  s.email = ["fguillen.mail@gmail.com", "cap10morgan@gmail.com"]
  s.extra_rdoc_files = ["README.md", "lib/simplecov-rcov.rb"]
  s.files = ["README.md", "lib/simplecov-rcov.rb"]
  s.homepage = "http://github.com/fguillen/simplecov-rcov"
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Simplecov-rcov", "--main", "README.md"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "simplecov-rcov"
  s.rubygems_version = "1.8.21"
  s.summary = "Rcov style formatter for SimpleCov"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<simplecov>, [">= 0.4.1"])
      s.add_development_dependency(%q<bundler>, [">= 1.0.0.rc.6"])
      s.add_development_dependency(%q<mocha>, [">= 0"])
      s.add_development_dependency(%q<rake>, [">= 0"])
    else
      s.add_dependency(%q<simplecov>, [">= 0.4.1"])
      s.add_dependency(%q<bundler>, [">= 1.0.0.rc.6"])
      s.add_dependency(%q<mocha>, [">= 0"])
      s.add_dependency(%q<rake>, [">= 0"])
    end
  else
    s.add_dependency(%q<simplecov>, [">= 0.4.1"])
    s.add_dependency(%q<bundler>, [">= 1.0.0.rc.6"])
    s.add_dependency(%q<mocha>, [">= 0"])
    s.add_dependency(%q<rake>, [">= 0"])
  end
end
