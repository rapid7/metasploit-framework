# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "sass"
  s.version = "3.1.15"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Nathan Weizenbaum", "Chris Eppstein", "Hampton Catlin"]
  s.date = "2012-02-09"
  s.description = "      Sass makes CSS fun again. Sass is an extension of CSS3, adding\n      nested rules, variables, mixins, selector inheritance, and more.\n      It's translated to well-formatted, standard CSS using the\n      command line tool or a web-framework plugin.\n"
  s.email = "sass-lang@googlegroups.com"
  s.executables = ["sass", "sass-convert", "scss"]
  s.files = ["bin/sass", "bin/sass-convert", "bin/scss"]
  s.homepage = "http://sass-lang.com/"
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubyforge_project = "sass"
  s.rubygems_version = "1.8.21"
  s.summary = "A powerful but elegant CSS compiler that makes CSS fun again."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<yard>, [">= 0.5.3"])
      s.add_development_dependency(%q<maruku>, [">= 0.5.9"])
    else
      s.add_dependency(%q<yard>, [">= 0.5.3"])
      s.add_dependency(%q<maruku>, [">= 0.5.9"])
    end
  else
    s.add_dependency(%q<yard>, [">= 0.5.3"])
    s.add_dependency(%q<maruku>, [">= 0.5.9"])
  end
end
