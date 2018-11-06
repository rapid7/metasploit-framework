# -*- encoding: utf-8 -*-
# stub: bindata 2.4.4 ruby lib

Gem::Specification.new do |s|
  s.name = "bindata".freeze
  s.version = "2.4.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Dion Mendel".freeze]
  s.date = "2018-10-03"
  s.description = "BinData is a declarative way to read and write binary file formats.\n\nThis means the programmer specifies *what* the format of the binary\ndata is, and BinData works out *how* to read and write data in this\nformat.  It is an easier ( and more readable ) alternative to\nruby's #pack and #unpack methods.\n".freeze
  s.email = "bindata@dm9.info".freeze
  s.extra_rdoc_files = ["NEWS.rdoc".freeze]
  s.files = ["NEWS.rdoc".freeze]
  s.homepage = "http://github.com/dmendel/bindata".freeze
  s.licenses = ["Ruby".freeze]
  s.rdoc_options = ["--main".freeze, "NEWS.rdoc".freeze]
  s.rubyforge_project = "bindata".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "A declarative way to read and write binary file formats".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<minitest>.freeze, ["> 5.0.0"])
      s.add_development_dependency(%q<coveralls>.freeze, [">= 0"])
    else
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<minitest>.freeze, ["> 5.0.0"])
      s.add_dependency(%q<coveralls>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<minitest>.freeze, ["> 5.0.0"])
    s.add_dependency(%q<coveralls>.freeze, [">= 0"])
  end
end
