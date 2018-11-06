# -*- encoding: utf-8 -*-
# stub: metasm 1.0.3 ruby .

Gem::Specification.new do |s|
  s.name = "metasm".freeze
  s.version = "1.0.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = [".".freeze]
  s.authors = ["Yoann Guillot".freeze]
  s.date = "2017-03-05"
  s.description = "".freeze
  s.email = ["john at ofjj.net".freeze]
  s.homepage = "http://metasm.cr0.org".freeze
  s.licenses = ["LGPL".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Metasm is a cross-architecture assembler, disassembler, linker, and debugger.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.7"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
    else
      s.add_dependency(%q<bundler>.freeze, ["~> 1.7"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.7"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
  end
end
