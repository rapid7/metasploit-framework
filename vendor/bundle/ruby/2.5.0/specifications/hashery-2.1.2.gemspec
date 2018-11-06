# -*- encoding: utf-8 -*-
# stub: hashery 2.1.2 ruby lib

Gem::Specification.new do |s|
  s.name = "hashery".freeze
  s.version = "2.1.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Trans".freeze, "Kirk Haines".freeze, "Robert Klemme".freeze, "Jan Molic".freeze, "George Moschovitis".freeze, "Jeena Paradies".freeze, "Erik Veenstra".freeze]
  s.date = "2016-05-01"
  s.description = "The Hashery is a tight collection of Hash-like classes. Included among its many offerings are the auto-sorting Dictionary class, the efficient LRUHash, the flexible OpenHash and the convenient KeyHash. Nearly every class is a subclass of the CRUDHash which defines a CRUD model on top of Ruby's standard Hash making it a snap to subclass and augment to fit any specific use case.".freeze
  s.email = ["transfire@gmail.com".freeze]
  s.extra_rdoc_files = ["LICENSE.txt".freeze, "NOTICE.txt".freeze, "HISTORY.md".freeze, "README.md".freeze]
  s.files = ["HISTORY.md".freeze, "LICENSE.txt".freeze, "NOTICE.txt".freeze, "README.md".freeze]
  s.homepage = "http://rubyworks.github.com/hashery".freeze
  s.licenses = ["BSD-2-Clause".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Facets-bread collection of Hash-like classes.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<qed>.freeze, [">= 0"])
      s.add_development_dependency(%q<lemon>.freeze, [">= 0"])
      s.add_development_dependency(%q<rubytest-cli>.freeze, [">= 0"])
    else
      s.add_dependency(%q<qed>.freeze, [">= 0"])
      s.add_dependency(%q<lemon>.freeze, [">= 0"])
      s.add_dependency(%q<rubytest-cli>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<qed>.freeze, [">= 0"])
    s.add_dependency(%q<lemon>.freeze, [">= 0"])
    s.add_dependency(%q<rubytest-cli>.freeze, [">= 0"])
  end
end
