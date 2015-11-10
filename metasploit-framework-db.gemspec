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
  spec.name          = 'metasploit-framework-db'
  spec.version       = Metasploit::Framework::GEM_VERSION
  spec.authors       = ['Metasploit Hackers']
  spec.email         = ['metasploit-hackers@lists.sourceforge.net']
  spec.summary       = 'metasploit-framework Database dependencies'
  spec.description   = 'Gems needed to access the PostgreSQL database in metasploit-framework'
  spec.homepage      = 'https://www.metasploit.com'
  spec.license       = 'BSD-3-clause'

  # no files, just dependencies
  spec.files         = []

  spec.add_runtime_dependency 'activerecord', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  # Metasploit::Credential database models
  spec.add_runtime_dependency 'metasploit-credential', '1.0.1'
  # Database models shared between framework and Pro.
  spec.add_runtime_dependency 'metasploit_data_models', '1.2.9'
  # depend on metasploit-framewrok as the optional gems are useless with the actual code
  spec.add_runtime_dependency 'metasploit-framework', "= #{spec.version}"
  # Needed for module caching in Mdm::ModuleDetails
  spec.add_runtime_dependency 'pg', '>= 0.11'
end
