# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rex/sslscan/version'

Gem::Specification.new do |spec|
  spec.name          = "rex-sslscan"
  spec.version       = Rex::Sslscan::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]

  spec.summary       = %q{Ruby Exploitation(REX) Library for scanning the SSL/TLS capabilities of a server}
  spec.description   = %q{This library is a pure ruby implmenetation of the SSLScan tool originally written
                          by Ian Ventura-Whiting. It currently depends on the system version of OpenSSL}
  spec.homepage      = "https://github.com/rapid7/rex-sslscan"


  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency "rex-core"
  spec.add_runtime_dependency "rex-text"
  spec.add_runtime_dependency "rex-socket"
end
