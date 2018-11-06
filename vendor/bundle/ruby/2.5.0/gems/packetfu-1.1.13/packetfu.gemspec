require 'rake'
require './lib/packetfu/version'

Gem::Specification.new do |s|
  s.name        = 'packetfu'
  s.version     = PacketFu::VERSION
  s.authors     = ['Tod Beardsley', 'Jonathan Claudius']
  s.email       = ['todb@packetfu.com', 'claudijd@yahoo.com']
  s.summary     = 'PacketFu is a mid-level packet manipulation library.'
  s.homepage    = 'https://github.com/packetfu/packetfu'
  s.description = %q{
    PacketFu is a mid-level packet manipulation library for Ruby. With
    it, users can read, parse, and write network packets with the level of
    ease and fun they expect from Ruby.
  }
  s.files       = `git ls-files`.split($/)
  s.license     = 'BSD'
  s.required_ruby_version = '>= 2.1.0'
  s.add_dependency('pcaprub')
  s.add_development_dependency('rake')
  s.add_development_dependency('rspec')
  s.add_development_dependency('rspec-its')
  s.add_development_dependency('sdoc')
  s.add_development_dependency('pry')
  s.add_development_dependency('coveralls')


  s.extra_rdoc_files  = %w[.document README.md]
  s.test_files        = (s.files & (Dir['spec/**/*_spec.rb'] + Dir['test/test_*.rb']) )
  s.rubyforge_project = 'packetfu'

  cert = File.expand_path("~/.ssh/gem-private_key_todb.pem")

  if File.exist?(cert) and File.readable?(cert)
    s.signing_key = cert
    s.cert_chain = ['gem-public_cert.pem']
  end

end
