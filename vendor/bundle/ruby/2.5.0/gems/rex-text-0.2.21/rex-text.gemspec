# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/text/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-text"
  spec.version       = Rex::Text::VERSION
  spec.authors       = ["David 'thelightcosine' Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = %q{Provides Text Manipulation Methods for Exploitation}
  spec.description   = %q{This Gem contains all of the Ruby Exploitation(Rex) methods for text manipulation and generation}
  spec.homepage      = "https://github.com/rapid7/rex-text"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
end
