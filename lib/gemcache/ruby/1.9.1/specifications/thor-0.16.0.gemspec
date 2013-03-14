# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "thor"
  s.version = "0.16.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.6") if s.respond_to? :required_rubygems_version=
  s.authors = ["Yehuda Katz", "Jos\u{e9} Valim"]
  s.date = "2012-08-14"
  s.description = "A scripting framework that replaces rake, sake and rubigen"
  s.email = "ruby-thor@googlegroups.com"
  s.executables = ["rake2thor", "thor"]
  s.extra_rdoc_files = ["CHANGELOG.rdoc", "LICENSE.md", "README.md", "Thorfile"]
  s.files = ["bin/rake2thor", "bin/thor", "CHANGELOG.rdoc", "LICENSE.md", "README.md", "Thorfile"]
  s.homepage = "http://whatisthor.com/"
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.24"
  s.summary = "A scripting framework that replaces rake, sake and rubigen"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>, ["~> 1.0"])
      s.add_development_dependency(%q<fakeweb>, ["~> 1.3"])
      s.add_development_dependency(%q<rake>, ["~> 0.9"])
      s.add_development_dependency(%q<rdoc>, ["~> 3.9"])
      s.add_development_dependency(%q<rspec>, ["~> 2.3"])
      s.add_development_dependency(%q<simplecov>, ["~> 0.4"])
      s.add_development_dependency(%q<childlabor>, [">= 0"])
    else
      s.add_dependency(%q<bundler>, ["~> 1.0"])
      s.add_dependency(%q<fakeweb>, ["~> 1.3"])
      s.add_dependency(%q<rake>, ["~> 0.9"])
      s.add_dependency(%q<rdoc>, ["~> 3.9"])
      s.add_dependency(%q<rspec>, ["~> 2.3"])
      s.add_dependency(%q<simplecov>, ["~> 0.4"])
      s.add_dependency(%q<childlabor>, [">= 0"])
    end
  else
    s.add_dependency(%q<bundler>, ["~> 1.0"])
    s.add_dependency(%q<fakeweb>, ["~> 1.3"])
    s.add_dependency(%q<rake>, ["~> 0.9"])
    s.add_dependency(%q<rdoc>, ["~> 3.9"])
    s.add_dependency(%q<rspec>, ["~> 2.3"])
    s.add_dependency(%q<simplecov>, ["~> 0.4"])
    s.add_dependency(%q<childlabor>, [">= 0"])
  end
end
