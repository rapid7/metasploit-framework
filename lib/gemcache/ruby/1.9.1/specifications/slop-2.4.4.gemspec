# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "slop"
  s.version = "2.4.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Lee Jarvis"]
  s.date = "2012-02-07"
  s.description = "A simple DSL for gathering options and parsing the command line"
  s.email = "lee@jarvis.co"
  s.homepage = "http://github.com/injekt/slop"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "Option gathering made easy"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
