# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "method_source"
  s.version = "0.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["John Mair (banisterfiend)"]
  s.date = "2012-07-05"
  s.description = "retrieve the sourcecode for a method"
  s.email = "jrmair@gmail.com"
  s.homepage = "http://banisterfiend.wordpress.com"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.24"
  s.summary = "retrieve the sourcecode for a method"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bacon>, ["~> 1.1.0"])
      s.add_development_dependency(%q<rake>, ["~> 0.9"])
    else
      s.add_dependency(%q<bacon>, ["~> 1.1.0"])
      s.add_dependency(%q<rake>, ["~> 0.9"])
    end
  else
    s.add_dependency(%q<bacon>, ["~> 1.1.0"])
    s.add_dependency(%q<rake>, ["~> 0.9"])
  end
end
