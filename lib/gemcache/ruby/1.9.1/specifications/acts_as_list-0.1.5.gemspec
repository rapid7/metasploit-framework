# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "acts_as_list"
  s.version = "0.1.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["David Heinemeier Hansson", "Swanand Pagnis", "Quinn Chaffee"]
  s.date = "2012-02-24"
  s.description = "This \"acts_as\" extension provides the capabilities for sorting and reordering a number of objects in a list. The class that has this specified needs to have a \"position\" column defined as an integer on the mapped database table."
  s.email = ["swanand.pagnis@gmail.com"]
  s.homepage = "http://github.com/swanandp/acts_as_list"
  s.require_paths = ["lib"]
  s.rubyforge_project = "acts_as_list"
  s.rubygems_version = "1.8.21"
  s.summary = "A gem allowing a active_record model to act_as_list."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>, ["~> 1.0.0"])
      s.add_development_dependency(%q<activerecord>, [">= 1.15.4.7794"])
      s.add_development_dependency(%q<rdoc>, [">= 0"])
      s.add_development_dependency(%q<sqlite3>, [">= 0"])
    else
      s.add_dependency(%q<bundler>, ["~> 1.0.0"])
      s.add_dependency(%q<activerecord>, [">= 1.15.4.7794"])
      s.add_dependency(%q<rdoc>, [">= 0"])
      s.add_dependency(%q<sqlite3>, [">= 0"])
    end
  else
    s.add_dependency(%q<bundler>, ["~> 1.0.0"])
    s.add_dependency(%q<activerecord>, [">= 1.15.4.7794"])
    s.add_dependency(%q<rdoc>, [">= 0"])
    s.add_dependency(%q<sqlite3>, [">= 0"])
  end
end
