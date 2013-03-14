# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "tzinfo"
  s.version = "0.3.33"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Philip Ross"]
  s.date = "2012-04-07"
  s.description = "TZInfo is a Ruby library that uses the standard tz (Olson) database to provide daylight savings aware transformations between times in different time zones."
  s.email = "phil.ross@gmail.com"
  s.extra_rdoc_files = ["README", "CHANGES"]
  s.files = ["README", "CHANGES"]
  s.homepage = "http://tzinfo.rubyforge.org/"
  s.rdoc_options = ["--exclude", "definitions", "--exclude", "indexes"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "tzinfo"
  s.rubygems_version = "1.8.21"
  s.summary = "Daylight-savings aware timezone library"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
