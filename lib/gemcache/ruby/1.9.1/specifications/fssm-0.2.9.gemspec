# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "fssm"
  s.version = "0.2.9"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Travis Tilley", "Nathan Weizenbaum", "Chris Eppstein", "Jonathan Castello", "Tuomas Kareinen"]
  s.date = "2012-04-09"
  s.description = "The File System State Monitor keeps track of the state of any number of paths and will fire events when said state changes (create/update/delete). FSSM supports using FSEvents on MacOS, Inotify on GNU/Linux, and polling anywhere else."
  s.email = ["ttilley@gmail.com"]
  s.homepage = "https://github.com/ttilley/fssm"
  s.require_paths = ["lib"]
  s.rubyforge_project = "fssm"
  s.rubygems_version = "1.8.21"
  s.summary = "File System State Monitor"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_development_dependency(%q<rspec>, [">= 2.4.0"])
    else
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<rspec>, [">= 2.4.0"])
    end
  else
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<rspec>, [">= 2.4.0"])
  end
end
