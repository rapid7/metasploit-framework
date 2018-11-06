# -*- encoding: utf-8 -*-
# stub: Ascii85 1.0.3 ruby lib

Gem::Specification.new do |s|
  s.name = "Ascii85".freeze
  s.version = "1.0.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Johannes Holzfu\u00DF".freeze]
  s.date = "2018-01-25"
  s.description = "Ascii85 provides methods to encode/decode Adobe's binary-to-text encoding of the same name.".freeze
  s.email = "johannes@holzfuss.name".freeze
  s.executables = ["ascii85".freeze]
  s.extra_rdoc_files = ["README.md".freeze, "LICENSE".freeze]
  s.files = ["LICENSE".freeze, "README.md".freeze, "bin/ascii85".freeze]
  s.homepage = "https://github.com/DataWraith/ascii85gem/".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Ascii85 encoder/decoder".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, [">= 1.0.0"])
      s.add_development_dependency(%q<minitest>.freeze, [">= 2.6.0"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0.9.2"])
    else
      s.add_dependency(%q<bundler>.freeze, [">= 1.0.0"])
      s.add_dependency(%q<minitest>.freeze, [">= 2.6.0"])
      s.add_dependency(%q<rake>.freeze, [">= 0.9.2"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, [">= 1.0.0"])
    s.add_dependency(%q<minitest>.freeze, [">= 2.6.0"])
    s.add_dependency(%q<rake>.freeze, [">= 0.9.2"])
  end
end
