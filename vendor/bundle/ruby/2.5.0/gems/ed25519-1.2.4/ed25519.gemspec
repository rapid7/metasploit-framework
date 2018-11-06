# frozen_string_literal: true

require File.expand_path("lib/ed25519/version", __dir__)

Gem::Specification.new do |spec|
  spec.name          = "ed25519"
  spec.version       = Ed25519::VERSION
  spec.authors       = ["Tony Arcieri"]
  spec.email         = ["tony.arcieri@gmail.com"]
  spec.summary       = "An efficient digital signature library providing the Ed25519 algorithm"
  spec.description = <<-DESCRIPTION.strip.gsub(/\s+/, " ")
    A Ruby binding to the Ed25519 elliptic curve public-key signature system
    described in RFC 8032.
  DESCRIPTION
  spec.homepage      = "https://github.com/crypto-rb/ed25519"
  spec.license       = "MIT"
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  if defined? JRUBY_VERSION
    spec.platform = "java"
    spec.files << "lib/ed25519_jruby.jar"
  else
    spec.platform   = Gem::Platform::RUBY
    spec.extensions = ["ext/ed25519_ref10/extconf.rb"]
  end

  spec.required_ruby_version = ">= 2.0.0"
  spec.add_development_dependency "bundler", "~> 1.16"
end
