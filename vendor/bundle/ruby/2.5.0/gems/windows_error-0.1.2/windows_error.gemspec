# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'windows_error/version'

Gem::Specification.new do |spec|
  spec.name          = "windows_error"
  spec.version       = WindowsError::VERSION
  spec.authors       = ["David Maloney"]
  spec.email         = ["DMaloney@rapid7.com"]
  spec.summary       = %q{Provides a way to look up Windows NTSTATUS and Win32 Error Codes}
  spec.description   = %q{The WindowsError gem provides an easily accessible reference for
                          standard Windows API Error Codes. It allows you to do comparisons
                          as well as direct lookups of error codes to translate the numerical
                          value returned by the API, into a meaningful and human readable message.}
  spec.homepage      = "https://github.com/rapid7/windows_error"
  spec.license       = "BSD"

  spec.required_ruby_version = '>= 2.2.0'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "yard"
  spec.add_development_dependency "fivemat"

end
