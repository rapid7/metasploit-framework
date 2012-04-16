# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "journey"
  s.version = "1.0.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Aaron Patterson"]
  s.date = "2012-02-22"
  s.description = "Journey is a router.  It routes requests."
  s.email = ["aaron@tenderlovemaking.com"]
  s.extra_rdoc_files = ["Manifest.txt", "CHANGELOG.rdoc", "README.rdoc"]
  s.files = ["Manifest.txt", "CHANGELOG.rdoc", "README.rdoc"]
  s.homepage = "http://github.com/rails/journey"
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "journey"
  s.rubygems_version = "1.8.21"
  s.summary = "Journey is a router"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<minitest>, ["~> 2.11"])
      s.add_development_dependency(%q<racc>, [">= 1.4.6"])
      s.add_development_dependency(%q<rdoc>, ["~> 3.11"])
      s.add_development_dependency(%q<json>, [">= 0"])
      s.add_development_dependency(%q<rdoc>, ["~> 3.10"])
      s.add_development_dependency(%q<hoe>, ["~> 2.13"])
    else
      s.add_dependency(%q<minitest>, ["~> 2.11"])
      s.add_dependency(%q<racc>, [">= 1.4.6"])
      s.add_dependency(%q<rdoc>, ["~> 3.11"])
      s.add_dependency(%q<json>, [">= 0"])
      s.add_dependency(%q<rdoc>, ["~> 3.10"])
      s.add_dependency(%q<hoe>, ["~> 2.13"])
    end
  else
    s.add_dependency(%q<minitest>, ["~> 2.11"])
    s.add_dependency(%q<racc>, [">= 1.4.6"])
    s.add_dependency(%q<rdoc>, ["~> 3.11"])
    s.add_dependency(%q<json>, [">= 0"])
    s.add_dependency(%q<rdoc>, ["~> 3.10"])
    s.add_dependency(%q<hoe>, ["~> 2.13"])
  end
end
