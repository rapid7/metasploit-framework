# -*- encoding: utf-8 -*-
# stub: packetfu 1.1.13 ruby lib

Gem::Specification.new do |s|
  s.name = "packetfu".freeze
  s.version = "1.1.13"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Tod Beardsley".freeze, "Jonathan Claudius".freeze]
  s.date = "2017-04-20"
  s.description = "\n    PacketFu is a mid-level packet manipulation library for Ruby. With\n    it, users can read, parse, and write network packets with the level of\n    ease and fun they expect from Ruby.\n  ".freeze
  s.email = ["todb@packetfu.com".freeze, "claudijd@yahoo.com".freeze]
  s.extra_rdoc_files = [".document".freeze, "README.md".freeze]
  s.files = [".document".freeze, "README.md".freeze]
  s.homepage = "https://github.com/packetfu/packetfu".freeze
  s.licenses = ["BSD".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1.0".freeze)
  s.rubyforge_project = "packetfu".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "PacketFu is a mid-level packet manipulation library.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<pcaprub>.freeze, [">= 0"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec-its>.freeze, [">= 0"])
      s.add_development_dependency(%q<sdoc>.freeze, [">= 0"])
      s.add_development_dependency(%q<pry>.freeze, [">= 0"])
      s.add_development_dependency(%q<coveralls>.freeze, [">= 0"])
    else
      s.add_dependency(%q<pcaprub>.freeze, [">= 0"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, [">= 0"])
      s.add_dependency(%q<rspec-its>.freeze, [">= 0"])
      s.add_dependency(%q<sdoc>.freeze, [">= 0"])
      s.add_dependency(%q<pry>.freeze, [">= 0"])
      s.add_dependency(%q<coveralls>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<pcaprub>.freeze, [">= 0"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, [">= 0"])
    s.add_dependency(%q<rspec-its>.freeze, [">= 0"])
    s.add_dependency(%q<sdoc>.freeze, [">= 0"])
    s.add_dependency(%q<pry>.freeze, [">= 0"])
    s.add_dependency(%q<coveralls>.freeze, [">= 0"])
  end
end
