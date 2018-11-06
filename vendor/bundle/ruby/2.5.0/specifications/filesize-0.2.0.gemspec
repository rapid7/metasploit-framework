# -*- encoding: utf-8 -*-
# stub: filesize 0.2.0 ruby lib

Gem::Specification.new do |s|
  s.name = "filesize".freeze
  s.version = "0.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Dominik Honnef".freeze]
  s.date = "2018-09-04"
  s.description = "filesize is a small class for handling filesizes with both the SI and binary prefixes, allowing conversion from any size to any other size.".freeze
  s.email = "dominikh@fork-bomb.org".freeze
  s.homepage = "https://github.com/dominikh/filesize".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.6".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "filesize is a small class for handling filesizes with both the SI and binary prefixes, allowing conversion from any size to any other size.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0"])
    else
      s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
    end
  else
    s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
  end
end
