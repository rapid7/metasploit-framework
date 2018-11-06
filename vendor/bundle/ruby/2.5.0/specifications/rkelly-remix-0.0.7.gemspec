# -*- encoding: utf-8 -*-
# stub: rkelly-remix 0.0.7 ruby lib

Gem::Specification.new do |s|
  s.name = "rkelly-remix".freeze
  s.version = "0.0.7"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Aaron Patterson".freeze, "Rene Saarsoo".freeze]
  s.date = "2015-01-14"
  s.description = "RKelly Remix is a fork of the\nRKelly[https://github.com/tenderlove/rkelly] JavaScript parser.".freeze
  s.email = ["aaron.patterson@gmail.com".freeze, "rene.saarsoo@sencha.com".freeze]
  s.extra_rdoc_files = ["CHANGELOG.rdoc".freeze, "Manifest.txt".freeze, "README.rdoc".freeze]
  s.files = ["CHANGELOG.rdoc".freeze, "Manifest.txt".freeze, "README.rdoc".freeze]
  s.homepage = "https://github.com/nene/rkelly-remix".freeze
  s.licenses = ["MIT".freeze]
  s.rdoc_options = ["--main".freeze, "README.rdoc".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "RKelly Remix is a fork of the RKelly[https://github.com/tenderlove/rkelly] JavaScript parser.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rdoc>.freeze, ["~> 4.0"])
      s.add_development_dependency(%q<hoe>.freeze, ["~> 3.13"])
    else
      s.add_dependency(%q<rdoc>.freeze, ["~> 4.0"])
      s.add_dependency(%q<hoe>.freeze, ["~> 3.13"])
    end
  else
    s.add_dependency(%q<rdoc>.freeze, ["~> 4.0"])
    s.add_dependency(%q<hoe>.freeze, ["~> 3.13"])
  end
end
