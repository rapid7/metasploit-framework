# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "sshkey/version"

Gem::Specification.new do |s|
  s.name        = "sshkey"
  s.version     = SSHKey::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["James Miller"]
  s.email       = ["bensie@gmail.com"]
  s.homepage    = "https://github.com/bensie/sshkey"
  s.summary     = %q{SSH private/public key generator in Ruby}
  s.description = %q{Generate private/public SSH keypairs using pure Ruby}
  s.licenses    = ["MIT"]

  s.rubyforge_project = "sshkey"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_development_dependency("rake")
  s.add_development_dependency("test-unit")
end
