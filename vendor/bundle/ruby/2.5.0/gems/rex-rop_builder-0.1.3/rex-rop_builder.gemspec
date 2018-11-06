# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/rop_builder/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-rop_builder"
  spec.version       = Rex::RopBuilder::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = %q{Ruby Exploitation(Rex) Library for building ROP chains.}
  spec.homepage      = "https://github.com/rapid7/rex-rop_builder"



  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "bin"
  spec.executables   = ["msfrop"]
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency "metasm"
  spec.add_runtime_dependency "rex-core"
  spec.add_runtime_dependency "rex-text"
end
