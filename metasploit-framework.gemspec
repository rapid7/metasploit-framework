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
require 'msf/util/helper'

Gem::Specification.new do |spec|
  spec.name          = 'metasploit-framework'
  spec.version       = Metasploit::Framework::GEM_VERSION
  spec.authors       = ['Metasploit Hackers']
  spec.email         = ['msfdev@metasploit.com']
  spec.summary       = 'metasploit-framework'
  spec.description   = 'metasploit-framework'
  spec.homepage      = 'https://www.metasploit.com'
  spec.license       = 'BSD-3-clause'

  # only do a git ls-files if the .git folder exists and we have a git binary in PATH
  if File.directory?(File.join(File.dirname(__FILE__), ".git")) && Msf::Util::Helper.which("git")
    spec.files         = `git ls-files`.split($/).reject { |file|
      file =~ /^documentation|^external/
    }
  end
  spec.bindir = '.'
  if ENV['CREATE_BINSTUBS']
    spec.executables   = [
      'msfconsole',
      'msfd',
      'msfrpc',
      'msfrpcd',
      'msfvenom'
    ]
  end
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.5'

  # Database support
  spec.add_runtime_dependency 'activerecord', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  # Need 3+ for ActiveSupport::Concern
  spec.add_runtime_dependency 'activesupport', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  # Needed for config.action_view for view plugin compatibility for Pro
  spec.add_runtime_dependency 'actionpack', *Metasploit::Framework::RailsVersionConstraint::RAILS_VERSION
  # Backports Ruby features across language versions
  spec.add_runtime_dependency 'backports'
  # Needed for some admin modules (cfme_manageiq_evm_pass_reset.rb)
  spec.add_runtime_dependency 'bcrypt', '3.1.12'
  # Needed for Javascript obfuscation
  spec.add_runtime_dependency 'jsobfu'
  # Needed for some admin modules (scrutinizer_add_user.rb)
  spec.add_runtime_dependency 'json'
  # Metasm compiler/decompiler/assembler
  spec.add_runtime_dependency 'metasm'
  # Metasploit::Concern hooks
  spec.add_runtime_dependency 'metasploit-concern'
  # Metasploit::Credential database models
  spec.add_runtime_dependency 'metasploit-credential'
  # Database models shared between framework and Pro.
  spec.add_runtime_dependency 'metasploit_data_models', '3.0.10'
  # Things that would normally be part of the database model, but which
  # are needed when there's no database
  spec.add_runtime_dependency 'metasploit-model'
  # Needed for Meterpreter
  spec.add_runtime_dependency 'metasploit-payloads', '1.3.79'
  # Needed for the next-generation POSIX Meterpreter
  spec.add_runtime_dependency 'metasploit_payloads-mettle', '0.5.16'
  # Needed by msfgui and other rpc components
  spec.add_runtime_dependency 'msgpack'
  # get list of network interfaces, like eth* from OS.
  spec.add_runtime_dependency 'network_interface'
  # NTLM authentication
  spec.add_runtime_dependency 'rubyntlm'
  # Needed by anemone crawler
  spec.add_runtime_dependency 'nokogiri'
  # Needed by db.rb and Msf::Exploit::Capture
  spec.add_runtime_dependency 'packetfu'
  # For sniffer and raw socket modules
  spec.add_runtime_dependency 'pcaprub'
  # Used by the Metasploit data model, etc.
  # bound to 0.2x for Activerecord 4.2.8 deprecation warnings:
  # https://github.com/ged/ruby-pg/commit/c90ac644e861857ae75638eb6954b1cb49617090
  spec.add_runtime_dependency 'pg', '~> 0.20'
  # Run initializers for metasploit-concern, metasploit-credential, metasploit_data_models Rails::Engines
  spec.add_runtime_dependency 'railties'
  # required for OS fingerprinting
  spec.add_runtime_dependency 'recog'
  # required for bitlocker fvek extraction
  spec.add_runtime_dependency 'openssl-ccm'
  # Needed for documentation generation
  spec.add_runtime_dependency 'octokit'
  spec.add_runtime_dependency 'redcarpet'
  # Needed for Microsoft patch finding tool (msu_finder)
  spec.add_runtime_dependency 'patch_finder'
  # Required for Metasploit Web Services
  spec.add_runtime_dependency 'thin'
  spec.add_runtime_dependency 'sinatra'
  spec.add_runtime_dependency 'warden'
  # Required for JSON-RPC client
  spec.add_runtime_dependency 'em-http-request'
  # TimeZone info
  spec.add_runtime_dependency 'tzinfo-data'
  # Gem for dealing with SSHKeys
  spec.add_runtime_dependency 'sshkey'
  # BitStruct Library used for handling certain Protocol Header/Packet construction
  spec.add_runtime_dependency 'bit-struct'
  # Library for interpreting Windows error codes and strings
  spec.add_runtime_dependency 'windows_error'
  # This used to be depended on by nokogiri, depended on by wmap
  if Gem::Version.new(RUBY_VERSION) >= Gem::Version.new('2.3.0')
    spec.add_runtime_dependency 'xmlrpc'
  end

  #
  # File Parsing Libraries
  #
  # Needed by auxiliary/gather/http_pdf_authors module
  spec.add_runtime_dependency 'pdf-reader'
  spec.add_runtime_dependency 'ruby-macho'

  #
  # Protocol Libraries
  #
  spec.add_runtime_dependency 'dnsruby'
  spec.add_runtime_dependency 'mqtt'
  spec.add_runtime_dependency 'net-ssh'
  spec.add_runtime_dependency 'ed25519' # Adds ed25519 keys for net-ssh
  spec.add_runtime_dependency 'bcrypt_pbkdf'
  spec.add_runtime_dependency 'ruby_smb'

  #
  # REX Libraries
  #
  # Core of the Ruby Exploitation Library
  spec.add_runtime_dependency 'rex-core'
  # Text manipulation library for things like generating random string
  spec.add_runtime_dependency 'rex-text'
  # Library for Generating Randomized strings valid as Identifiers such as variable names
  spec.add_runtime_dependency 'rex-random_identifier'
  # library for creating Powershell scripts for exploitation purposes
  spec.add_runtime_dependency 'rex-powershell'
  # Library for processing and creating Zip compatbile archives
  spec.add_runtime_dependency 'rex-zip'
  # Library for parsing offline Windows Registry files
  spec.add_runtime_dependency 'rex-registry'
  # Library for parsing Java serialized streams
  spec.add_runtime_dependency 'rex-java'
  # Library for C-style structs
  spec.add_runtime_dependency 'rex-struct2'
  # Library which contains architecture specific information such as registers, opcodes,
  # and stack manipulation routines.
  spec.add_runtime_dependency 'rex-arch'
  # Library for working with OLE.
  spec.add_runtime_dependency 'rex-ole'
  # Library for creating and/or parsing MIME messages.
  spec.add_runtime_dependency 'rex-mime'
  # Library for Dynamic Multi-byte x86 NOP generation
  spec.add_runtime_dependency 'rex-nop'
  # Library for parsing and manipulating executable binaries
  spec.add_runtime_dependency 'rex-bin_tools'
  # Rex Socket Abstraction Layer
  spec.add_runtime_dependency 'rex-socket'
  # Library for scanning a server's SSL/TLS capabilities
  spec.add_runtime_dependency 'rex-sslscan'
  # Library and tool for finding ROP gadgets in a supplied binary
  spec.add_runtime_dependency 'rex-rop_builder'
  # Library for polymorphic encoders; used for payload encoding
  spec.add_runtime_dependency 'rex-encoder'
  # Library for exploit development helpers
  spec.add_runtime_dependency 'rex-exploitation'
  # Command line editing, history, and tab completion in msfconsole
  spec.add_runtime_dependency 'rb-readline'
  # Needed by some modules
  spec.add_runtime_dependency 'rubyzip'
  # Needed for some post modules
  spec.add_runtime_dependency 'sqlite3'
  # required for Time::TZInfo in ActiveSupport
  spec.add_runtime_dependency 'tzinfo'
  # Needed so that disk size output isn't horrible
  spec.add_runtime_dependency 'filesize'
  # Needed for openvas plugin
  spec.add_runtime_dependency 'openvas-omp'
  # Needed by metasploit nessus bridge
  spec.add_runtime_dependency 'nessus_rest'
  # Nexpose Gem
  spec.add_runtime_dependency 'nexpose'
  # Needed for NDMP sockets
  spec.add_runtime_dependency 'xdr'
  # Needed for ::Msf...CertProvider
  spec.add_runtime_dependency 'faker'
  # Pinned as a dependency of i18n to the last working version
  spec.add_runtime_dependency 'concurrent-ruby','1.0.5'

  # AWS enumeration modules
  spec.add_runtime_dependency 'aws-sdk-s3'
  spec.add_runtime_dependency 'aws-sdk-ec2'
  spec.add_runtime_dependency 'aws-sdk-iam'
  
  # Earlier than latest Faraday gem is used to prevent upstream Octokit errors
  spec.add_runtime_dependency 'faraday', '0.17.0'

end
