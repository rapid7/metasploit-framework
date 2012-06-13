# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "carrierwave"
  s.version = "0.6.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Jonas Nicklas"]
  s.date = "2012-04-12"
  s.description = "Upload files in your Ruby applications, map them to a range of ORMs, store them on different backends."
  s.email = ["jonas.nicklas@gmail.com"]
  s.extra_rdoc_files = ["README.md"]
  s.files = ["README.md"]
  s.homepage = "https://github.com/jnicklas/carrierwave"
  s.rdoc_options = ["--main"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "carrierwave"
  s.rubygems_version = "1.8.15"
  s.summary = "Ruby file upload library"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activesupport>, [">= 3.2.0"])
      s.add_runtime_dependency(%q<activemodel>, [">= 3.2.0"])
      s.add_development_dependency(%q<mysql2>, [">= 0"])
      s.add_development_dependency(%q<rails>, [">= 3.2.0"])
      s.add_development_dependency(%q<cucumber>, ["= 1.1.4"])
      s.add_development_dependency(%q<json>, [">= 0"])
      s.add_development_dependency(%q<rspec>, ["~> 2.0"])
      s.add_development_dependency(%q<sham_rack>, [">= 0"])
      s.add_development_dependency(%q<timecop>, [">= 0"])
      s.add_development_dependency(%q<fog>, [">= 1.3.1"])
      s.add_development_dependency(%q<mini_magick>, [">= 0"])
      s.add_development_dependency(%q<rmagick>, [">= 0"])
    else
      s.add_dependency(%q<activesupport>, [">= 3.2.0"])
      s.add_dependency(%q<activemodel>, [">= 3.2.0"])
      s.add_dependency(%q<mysql2>, [">= 0"])
      s.add_dependency(%q<rails>, [">= 3.2.0"])
      s.add_dependency(%q<cucumber>, ["= 1.1.4"])
      s.add_dependency(%q<json>, [">= 0"])
      s.add_dependency(%q<rspec>, ["~> 2.0"])
      s.add_dependency(%q<sham_rack>, [">= 0"])
      s.add_dependency(%q<timecop>, [">= 0"])
      s.add_dependency(%q<fog>, [">= 1.3.1"])
      s.add_dependency(%q<mini_magick>, [">= 0"])
      s.add_dependency(%q<rmagick>, [">= 0"])
    end
  else
    s.add_dependency(%q<activesupport>, [">= 3.2.0"])
    s.add_dependency(%q<activemodel>, [">= 3.2.0"])
    s.add_dependency(%q<mysql2>, [">= 0"])
    s.add_dependency(%q<rails>, [">= 3.2.0"])
    s.add_dependency(%q<cucumber>, ["= 1.1.4"])
    s.add_dependency(%q<json>, [">= 0"])
    s.add_dependency(%q<rspec>, ["~> 2.0"])
    s.add_dependency(%q<sham_rack>, [">= 0"])
    s.add_dependency(%q<timecop>, [">= 0"])
    s.add_dependency(%q<fog>, [">= 1.3.1"])
    s.add_dependency(%q<mini_magick>, [">= 0"])
    s.add_dependency(%q<rmagick>, [">= 0"])
  end
end
