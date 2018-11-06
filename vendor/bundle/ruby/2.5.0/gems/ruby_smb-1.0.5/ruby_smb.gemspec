# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ruby_smb/version'

Gem::Specification.new do |spec|
  spec.name          = 'ruby_smb'
  spec.version       = RubySMB::VERSION
  spec.authors       = ['David Maloney', 'James Lee', 'Dev Mohanty', 'Christophe De La Fuente']
  spec.email         = ['DMaloney@rapid7.com', 'egypt@metasploit.com', 'dev_mohanty@rapid7.com', 'paristvinternet-github@yahoo.com']
  spec.summary       = 'A pure Ruby implementation of the SMB Protocol Family'
  spec.description   = ''
  spec.homepage      = 'https://github.com/rapid7/ruby_smb'
  spec.license       = 'BSD-3-clause'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  if RUBY_PLATFORM =~ /java/
    spec.add_development_dependency 'kramdown'
    spec.platform = Gem::Platform::JAVA
  else
    spec.add_development_dependency 'redcarpet'
    spec.platform = Gem::Platform::RUBY
  end

  spec.required_ruby_version = '>= 2.2.0'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'fivemat'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'yard'

  spec.add_runtime_dependency 'rubyntlm'
  spec.add_runtime_dependency 'windows_error'
  spec.add_runtime_dependency 'bindata'
end
