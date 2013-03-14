# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "msgpack"
  s.version = "0.4.6"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["FURUHASHI Sadayuki"]
  s.date = "2011-08-08"
  s.email = "frsyuki@users.sourceforge.jp"
  s.extensions = ["ext/extconf.rb"]
  s.files = ["ext/extconf.rb"]
  s.homepage = "http://msgpack.org/"
  s.rdoc_options = ["ext"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "msgpack"
  s.rubygems_version = "1.8.21"
  s.summary = "MessagePack, a binary-based efficient data interchange format."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
