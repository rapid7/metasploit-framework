# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'backports/version'

Gem::Specification.new do |gem|
  gem.name          = "backports"
  gem.version       = Backports::VERSION
  gem.authors       = ["Marc-André Lafortune"]
  gem.email         = ["github@marc-andre.ca"]
  gem.description   = %q{Essential backports that enable many of the nice features of Ruby 1.8.7 up to 2.1.0 for earlier versions.}
  gem.summary       = %q{Backports of Ruby features for older Ruby.}
  gem.homepage      = "http://github.com/marcandre/backports"
  gem.license       = "MIT"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
end
