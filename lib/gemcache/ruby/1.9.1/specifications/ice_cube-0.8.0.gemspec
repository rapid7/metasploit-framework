# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "ice_cube"
  s.version = "0.8.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["John Crepezzi"]
  s.date = "2012-03-25"
  s.description = "ice_cube is a recurring date library for Ruby.  It allows for quick, programatic expansion of recurring date rules."
  s.email = "john@crepezzi.com"
  s.homepage = "http://seejohnrun.github.com/ice_cube/"
  s.require_paths = ["lib"]
  s.rubyforge_project = "ice-cube"
  s.rubygems_version = "1.8.21"
  s.summary = "Ruby Date Recurrence Library"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>, [">= 0"])
      s.add_development_dependency(%q<active_support>, [">= 3.0.0"])
      s.add_development_dependency(%q<tzinfo>, [">= 0"])
    else
      s.add_dependency(%q<rspec>, [">= 0"])
      s.add_dependency(%q<active_support>, [">= 3.0.0"])
      s.add_dependency(%q<tzinfo>, [">= 0"])
    end
  else
    s.add_dependency(%q<rspec>, [">= 0"])
    s.add_dependency(%q<active_support>, [">= 3.0.0"])
    s.add_dependency(%q<tzinfo>, [">= 0"])
  end
end
