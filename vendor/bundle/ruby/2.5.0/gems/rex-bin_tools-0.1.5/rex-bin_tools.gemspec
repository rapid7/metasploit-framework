# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/bin_tools/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-bin_tools"
  spec.version       = Rex::BinTools::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = "Ruby Exploitation(rex) Library containing a suite of binary reading and manipulation tools"
  spec.description   = "A suite of tools for analyzing Elf,Mach, and PE format executables to find specific chunks of code."
  spec.homepage      = "https://github.com/rapid7/rex-bin_tools"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "bin"
  spec.executables   = ["msfbinscan", "msfelfscan", "msfmachscan", "msfpescan"]
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency 'metasm'
  spec.add_runtime_dependency 'rex-arch'
  spec.add_runtime_dependency 'rex-struct2'
  spec.add_runtime_dependency 'rex-text'
  spec.add_runtime_dependency 'rex-core'
end
