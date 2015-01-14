# coding: utf-8

# During build, the Gemfile is temporarily moved and
# we must manually define the project root
if ENV['MSF_ROOT']
  lib = File.realpath(File.expand_path('lib', ENV['MSF_ROOT']))
else
  # have to use realpath as metasploit-framework is often loaded through a symlink and tools like Coverage and debuggers
  # require realpaths.
  lib = File.realpath(File.expand_path('../lib', __FILE__))
end

$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'metasploit/framework/version'
require 'metasploit/framework/rails_version_constraint'

Gem::Specification.new do |spec|
  spec.name          = 'metasploit-framework-full'
  spec.version       = Metasploit::Framework::GEM_VERSION
  spec.authors       = ['Metasploit Hackers']
  spec.email         = ['metasploit-hackers@lists.sourceforge.net']
  spec.summary       = 'metasploit-framework with all optional dependencies'
  spec.description   = 'Gems needed to access the PostgreSQL database in metasploit-framework'
  spec.homepage      = 'https://www.metasploit.com'
  spec.license       = 'BSD-3-clause'

  # no files, just dependencies
  spec.files         = []

  metasploit_framework_version_constraint = "= #{spec.version}"

  spec.add_runtime_dependency 'rails', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  spec.add_runtime_dependency 'metasploit-framework', metasploit_framework_version_constraint
  spec.add_runtime_dependency 'metasploit-framework-db', metasploit_framework_version_constraint
  spec.add_runtime_dependency 'metasploit-framework-pcap', metasploit_framework_version_constraint
end
