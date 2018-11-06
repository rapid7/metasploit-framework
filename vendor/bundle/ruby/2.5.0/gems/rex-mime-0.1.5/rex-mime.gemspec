# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/mime/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-mime"
  spec.version       = Rex::Mime::VERSION
  spec.authors       = ["dmohanty-r7"]
  spec.email         = ["Dev_Mohanty@rapid7.com"]

  spec.summary       = %q{This library is for creating and/or parsing MIME messages.}
  spec.description   = %q{This library is for creating and/or parsing MIME messages.}
  spec.homepage      = "https://github.com/rapid7/rex-mime"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"

  spec.add_runtime_dependency "rex-text"
end
