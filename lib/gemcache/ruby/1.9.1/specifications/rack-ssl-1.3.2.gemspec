# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rack-ssl"
  s.version = "1.3.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joshua Peek"]
  s.date = "2011-03-24"
  s.description = "    Rack middleware to force SSL/TLS.\n"
  s.email = "josh@joshpeek.com"
  s.homepage = "https://github.com/josh/rack-ssl"
  s.require_paths = ["lib"]
  s.rubyforge_project = "rack-ssl"
  s.rubygems_version = "1.8.21"
  s.summary = "Force SSL/TLS in your app."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rack>, [">= 0"])
    else
      s.add_dependency(%q<rack>, [">= 0"])
    end
  else
    s.add_dependency(%q<rack>, [">= 0"])
  end
end
