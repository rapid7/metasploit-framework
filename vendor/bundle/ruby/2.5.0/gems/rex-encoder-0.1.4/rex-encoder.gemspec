# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/encoder/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-encoder"
  spec.version       = Rex::Encoder::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = %q{Ruby Exploitation(Rex) library for various polymorphic encoders.}
  spec.description   = %q{This library provides the basis for all of the polymorphic encoders
                          that Metasploit uses for payload encoding. Encoders are used to try and create
                          a version of a payload that is free of bad characters as defined by the exploit. }
  spec.homepage      = "https://github.com/rapid7/rex-encoder"


  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency "rex-arch"
  spec.add_runtime_dependency "metasm"
  spec.add_runtime_dependency "rex-text"
end
