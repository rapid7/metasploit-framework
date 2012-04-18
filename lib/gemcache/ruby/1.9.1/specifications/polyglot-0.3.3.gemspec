# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "polyglot"
  s.version = "0.3.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Clifford Heath"]
  s.date = "2011-11-01"
  s.description = "\nThe Polyglot library allows a Ruby module to register a loader\nfor the file type associated with a filename extension, and it\naugments 'require' to find and load matching files."
  s.email = ["clifford.heath@gmail.com"]
  s.extra_rdoc_files = ["README.txt"]
  s.files = ["README.txt"]
  s.homepage = "http://github.com/cjheath/polyglot"
  s.licenses = ["MIT"]
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "Augment 'require' to load non-Ruby file types"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
