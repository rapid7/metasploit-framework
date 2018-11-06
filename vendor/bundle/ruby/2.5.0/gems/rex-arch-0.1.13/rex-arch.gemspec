# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/arch/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-arch"
  spec.version       = Rex::Arch::VERSION
  spec.authors       = ["dmohanty-r7"]
  spec.email         = ["Dev_Mohanty@rapid7.com"]
  spec.license       = "BSD-3-Clause"

  spec.summary       = %q{Ruby Exploitation Library - rex-arch}
  spec.description   = %q{This library contains architecture specific information such as registers, opcodes, and stack manipulation routines.}
  spec.homepage      = "https://github.com/rapid7/rex-arch"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"

  spec.add_runtime_dependency "rex-text"
end
