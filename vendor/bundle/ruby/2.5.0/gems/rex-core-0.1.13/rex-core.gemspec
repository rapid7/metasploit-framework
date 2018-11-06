# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/core/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-core"
  spec.version       = Rex::Core::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = %q{Core libraries required for the Ruby Exploitation (Rex) Suite.}
  spec.description   = %q{Core libraries required for the Ruby Exploitation (Rex) Suite.
    Rex provides a variety of classes useful for security testing and exploit development.}
  spec.homepage      = "https://github.com/rapid7/rex-core"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
