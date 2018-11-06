# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/nop/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-nop"
  spec.version       = Rex::Nop::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = %q{Ruby Exploitation(REX) library for NOP generation. }
  spec.description   = %q{This library contains the opty2 library for dynamic generation of x86 multi-byte NOPs.
                          This is useful in writing exploits and encoders. It allows you to dynamic generate variable
                          length instruction sets that are equivalent to a No Operation(NOP) without using
                          the actual 0x90 bytecode. The original code was written by Optyx and spoonm. }
  spec.homepage      = "https://github.com/rapid7/rex-nop"


  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency "rex-arch"
end
