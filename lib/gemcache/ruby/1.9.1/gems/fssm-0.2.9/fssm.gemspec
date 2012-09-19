# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "fssm/version"

Gem::Specification.new do |s|
  s.name              = "fssm"
  s.version           = FSSM::VERSION
  s.platform          = Gem::Platform::RUBY
  s.authors           = ["Travis Tilley", "Nathan Weizenbaum", "Chris Eppstein",
                         "Jonathan Castello", "Tuomas Kareinen"]
  s.email             = ["ttilley@gmail.com"]
  s.homepage          = "https://github.com/ttilley/fssm"
  s.summary           = %q{File System State Monitor}
  s.description       = %q{The File System State Monitor keeps track of the state of any number of paths and will fire events when said state changes (create/update/delete). FSSM supports using FSEvents on MacOS, Inotify on GNU/Linux, and polling anywhere else.}

  s.rubyforge_project = "fssm"

  s.files             = `git ls-files`.split("\n")
  s.test_files        = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables       = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths     = ["lib"]
  
#  s.extensions        = 'ext/rakefile.rb'

  s.add_development_dependency "rake"
  s.add_development_dependency "rspec", ">= 2.4.0"
end
