
require_relative 'lib/net/ssh/version'

Gem::Specification.new do |spec|
  spec.name          = "net-ssh"
  spec.version       = Net::SSH::Version::STRING
  spec.authors       = ["Jamis Buck", "Delano Mandelbaum", "Mikl\u{f3}s Fazekas"]
  spec.email         = ["net-ssh@solutious.com"]

  if ENV['NET_SSH_BUILDGEM_SIGNED']
    spec.cert_chain = ["net-ssh-public_cert.pem"]
    spec.signing_key = "/mnt/gem/net-ssh-private_key.pem"
  end

  spec.summary       = %q{Net::SSH: a pure-Ruby implementation of the SSH2 client protocol.}
  spec.description   = %q{Net::SSH: a pure-Ruby implementation of the SSH2 client protocol. It allows you to write programs that invoke and interact with processes on remote servers, via SSH2.}
  spec.homepage      = "https://github.com/net-ssh/net-ssh"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.2.6")

  spec.extra_rdoc_files = [
    "LICENSE.txt",
    "README.rdoc"
  ]

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  unless ENV['NET_SSH_NO_ED25519']
    spec.add_development_dependency("bcrypt_pbkdf", "~> 1.0") unless RUBY_PLATFORM == "java"
    spec.add_development_dependency("ed25519", "~> 1.2")
  end

  spec.add_development_dependency "bundler", "~> 1.11"

  spec.add_development_dependency "minitest", "~> 5.10"
  spec.add_development_dependency "mocha", ">= 1.2.1"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "rubocop", "~> 0.54.0"
end
