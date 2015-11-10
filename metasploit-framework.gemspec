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
  spec.name          = 'metasploit-framework'
  spec.version       = Metasploit::Framework::GEM_VERSION
  spec.authors       = ['Metasploit Hackers']
  spec.email         = ['metasploit-hackers@lists.sourceforge.net']
  spec.summary       = 'metasploit-framework'
  spec.description   = 'metasploit-framework'
  spec.homepage      = 'https://www.metasploit.com'
  spec.license       = 'BSD-3-clause'

  spec.files         = `git ls-files`.split($/).reject { |file|
    file =~ /^config/
  }
  spec.bindir = '.'
  spec.executables   = [
      'msfbinscan',
      'msfconsole',
      'msfd',
      'msfelfscan',
      'msfmachscan',
      'msfpescan',
      'msfrop',
      'msfrpc',
      'msfrpcd',
      'msfupdate',
      'msfvenom'
  ]
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ["lib"]


  # Need 3+ for ActiveSupport::Concern
  spec.add_runtime_dependency 'activesupport', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  # Needed for config.action_view for view plugin compatibility for Pro
  spec.add_runtime_dependency 'actionpack', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  # Needed for some admin modules (cfme_manageiq_evm_pass_reset.rb)
  spec.add_runtime_dependency 'bcrypt'
  # Needed for Javascript obfuscation
  spec.add_runtime_dependency 'jsobfu', '~> 0.3.0'
  # Needed for some admin modules (scrutinizer_add_user.rb)
  spec.add_runtime_dependency 'json'
  # Metasm compiler/decompiler/assembler
  spec.add_runtime_dependency 'metasm', '~> 1.0.2'
  # Metasploit::Concern hooks
  spec.add_runtime_dependency 'metasploit-concern', '1.0.0'
  # Things that would normally be part of the database model, but which
  # are needed when there's no database
  spec.add_runtime_dependency 'metasploit-model', '1.0.0'
  # Needed for Meterpreter
  spec.add_runtime_dependency 'metasploit-payloads', '1.0.16'
  # Needed by msfgui and other rpc components
  spec.add_runtime_dependency 'msgpack'
  # Needed by anemone crawler
  spec.add_runtime_dependency 'nokogiri'
  # Needed by db.rb and Msf::Exploit::Capture
  spec.add_runtime_dependency 'packetfu', '1.1.11'
  # Run initializers for metasploit-concern, metasploit-credential, metasploit_data_models Rails::Engines
  spec.add_runtime_dependency 'railties'
  # required for OS fingerprinting
  spec.add_runtime_dependency 'recog', '2.0.14'

  # rb-readline doesn't work with Ruby Installer due to error with Fiddle:
  #   NoMethodError undefined method `dlopen' for Fiddle:Module
  unless Gem.win_platform?
    # Command line editing, history, and tab completion in msfconsole
    # Use the Rapid7 fork until the official gem catches up
    spec.add_runtime_dependency 'rb-readline-r7'
  end

  # Needed by anemone crawler
  spec.add_runtime_dependency 'robots'
  # Needed by some modules
  spec.add_runtime_dependency 'rubyzip', '~> 1.1'
  # Needed for some post modules
  spec.add_runtime_dependency 'sqlite3'
  # required for Time::TZInfo in ActiveSupport
  spec.add_runtime_dependency 'tzinfo'
  # Needed so that disk size output isn't horrible
  spec.add_runtime_dependency 'filesize'
end
