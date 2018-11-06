# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'swagger/blocks/version'

Gem::Specification.new do |spec|
  spec.name          = 'swagger-blocks'
  spec.version       = Swagger::Blocks::VERSION
  spec.authors       = ['Mike Fotinakis']
  spec.email         = ['mike@fotinakis.com']
  spec.summary       = %q{Define and serve live-updating Swagger JSON for Ruby apps.}
  spec.description   = %q{}
  spec.homepage      = 'https://github.com/fotinakis/swagger-blocks'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 1.9.3'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'pry'
end
