# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "authlogic"
  s.version = "3.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Ben Johnson of Binary Logic"]
  s.date = "2011-10-19"
  s.email = "bjohnson@binarylogic.com"
  s.extra_rdoc_files = ["LICENSE", "README.rdoc"]
  s.files = ["LICENSE", "README.rdoc"]
  s.homepage = "http://github.com/binarylogic/authlogic"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "A clean, simple, and unobtrusive ruby authentication solution."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activerecord>, [">= 3.0.7"])
      s.add_runtime_dependency(%q<activerecord>, [">= 3.0.7"])
    else
      s.add_dependency(%q<activerecord>, [">= 3.0.7"])
      s.add_dependency(%q<activerecord>, [">= 3.0.7"])
    end
  else
    s.add_dependency(%q<activerecord>, [">= 3.0.7"])
    s.add_dependency(%q<activerecord>, [">= 3.0.7"])
  end
end
