# -*- encoding: utf-8 -*-
# stub: sinatra 1.4.8 ruby lib

Gem::Specification.new do |s|
  s.name = "sinatra".freeze
  s.version = "1.4.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Blake Mizerany".freeze, "Ryan Tomayko".freeze, "Simon Rozet".freeze, "Konstantin Haase".freeze]
  s.date = "2017-01-30"
  s.description = "Sinatra is a DSL for quickly creating web applications in Ruby with minimal effort.".freeze
  s.email = "sinatrarb@googlegroups.com".freeze
  s.extra_rdoc_files = ["README.de.md".freeze, "README.es.md".freeze, "README.fr.md".freeze, "README.hu.md".freeze, "README.ja.md".freeze, "README.ko.md".freeze, "README.md".freeze, "README.pt-br.md".freeze, "README.pt-pt.md".freeze, "README.ru.md".freeze, "README.zh.md".freeze, "LICENSE".freeze]
  s.files = ["LICENSE".freeze, "README.de.md".freeze, "README.es.md".freeze, "README.fr.md".freeze, "README.hu.md".freeze, "README.ja.md".freeze, "README.ko.md".freeze, "README.md".freeze, "README.pt-br.md".freeze, "README.pt-pt.md".freeze, "README.ru.md".freeze, "README.zh.md".freeze]
  s.homepage = "http://www.sinatrarb.com/".freeze
  s.licenses = ["MIT".freeze]
  s.rdoc_options = ["--line-numbers".freeze, "--inline-source".freeze, "--title".freeze, "Sinatra".freeze, "--main".freeze, "README.rdoc".freeze, "--encoding=UTF-8".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Classy web-development dressed in a DSL".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rack>.freeze, ["~> 1.5"])
      s.add_runtime_dependency(%q<tilt>.freeze, ["< 3", ">= 1.3"])
      s.add_runtime_dependency(%q<rack-protection>.freeze, ["~> 1.4"])
    else
      s.add_dependency(%q<rack>.freeze, ["~> 1.5"])
      s.add_dependency(%q<tilt>.freeze, ["< 3", ">= 1.3"])
      s.add_dependency(%q<rack-protection>.freeze, ["~> 1.4"])
    end
  else
    s.add_dependency(%q<rack>.freeze, ["~> 1.5"])
    s.add_dependency(%q<tilt>.freeze, ["< 3", ">= 1.3"])
    s.add_dependency(%q<rack-protection>.freeze, ["~> 1.4"])
  end
end
