# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "metasploit_data_models/version"

Gem::Specification.new do |s|
  s.name        = "metasploit_data_models"
  s.version     = MetasploitDataModels::VERSION
  s.authors     = ["Trevor Rosen"]
  s.email       = ["trevor_rosen@rapid7.com"]
  s.homepage    = ""
  s.summary     = %q{Database code for MSF and Metasploit Pro}
  s.description = %q{Implements minimal ActiveRecord models and database helper code used in both the Metasploit Framework (MSF) and Metasploit commercial editions.}

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # ---- Dependencies ----
  s.add_development_dependency 'rake'

  s.add_runtime_dependency 'activerecord'
  s.add_runtime_dependency 'activesupport'
  s.add_runtime_dependency 'pg'
  s.add_runtime_dependency 'pry'
end
