# -*- encoding: utf-8 -*-
# stub: openvas-omp 0.0.4 ruby lib

Gem::Specification.new do |s|
  s.name = "openvas-omp".freeze
  s.version = "0.0.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vlatko Kosturjak".freeze]
  s.date = "2011-01-10"
  s.description = "Communicate with OpenVAS manager through OMP. \nThis library is used for communication with OpenVAS manager over OMP.\nYou can start, stop, pause and resume scan. Watch progress and status of\nscan, download report, etc.".freeze
  s.email = "vlatko.kosturjak@gmail.com".freeze
  s.extra_rdoc_files = ["LICENSE.txt".freeze, "README.rdoc".freeze, "TODO".freeze]
  s.files = ["LICENSE.txt".freeze, "README.rdoc".freeze, "TODO".freeze]
  s.homepage = "http://github.com/kost/openvas-omp".freeze
  s.licenses = ["MIT".freeze]
  s.rubyforge_project = "openvas-omp".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Communicate with OpenVAS manager through OMP".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<shoulda>.freeze, [">= 0"])
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.0.0"])
      s.add_development_dependency(%q<jeweler>.freeze, ["~> 1.5.2"])
      s.add_development_dependency(%q<rcov>.freeze, [">= 0"])
    else
      s.add_dependency(%q<shoulda>.freeze, [">= 0"])
      s.add_dependency(%q<bundler>.freeze, ["~> 1.0.0"])
      s.add_dependency(%q<jeweler>.freeze, ["~> 1.5.2"])
      s.add_dependency(%q<rcov>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<shoulda>.freeze, [">= 0"])
    s.add_dependency(%q<bundler>.freeze, ["~> 1.0.0"])
    s.add_dependency(%q<jeweler>.freeze, ["~> 1.5.2"])
    s.add_dependency(%q<rcov>.freeze, [">= 0"])
  end
end
