# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/ole/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-ole"
  spec.version       = Rex::OLE::VERSION
  spec.authors       = ["Pearce Barry"]
  spec.email         = ["pearce_barry@rapid7.com"]

  spec.summary       = %q{Rex Library for working with OLE}
  spec.description   = %q{Ruby Exploitation(Rex) library gem for reading/writing Object-Linking-and-Embedding (OLE) files and streams}
  spec.homepage      = "https://github.com/rapid7/rex-ole"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency "rex-text"
end
