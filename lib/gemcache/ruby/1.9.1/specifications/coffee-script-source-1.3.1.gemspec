# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "coffee-script-source"
  s.version = "1.3.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Jeremy Ashkenas"]
  s.date = "2012-04-10"
  s.description = "      CoffeeScript is a little language that compiles into JavaScript.\n      Underneath all of those embarrassing braces and semicolons,\n      JavaScript has always had a gorgeous object model at its heart.\n      CoffeeScript is an attempt to expose the good parts of JavaScript\n      in a simple way.\n"
  s.email = "jashkenas@gmail.com"
  s.homepage = "http://jashkenas.github.com/coffee-script/"
  s.require_paths = ["lib"]
  s.rubyforge_project = "coffee-script-source"
  s.rubygems_version = "1.8.21"
  s.summary = "The CoffeeScript Compiler"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
