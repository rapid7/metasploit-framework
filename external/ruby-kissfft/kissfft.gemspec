# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name        = "kissfft"
  s.version     = "0.0.1"
  s.authors     = ["HD Moore"]
  s.email       = ["hdm@rapid7.com"]
  s.homepage    = ""
  s.summary     = %q{Ruby wrapper around the KisFFT library for performing FFTs}
  s.description = %q{Provides access to the KissFFT library for performing fast-fourier transforms from Ruby }

  s.files         = Dir.glob('lib/**/*.rb') + Dir.glob('ext/**/*.{c,h,rb}') + [ "LICENSE" ]
  s.test_files    = Dir.glob('test/**/*.{rb,data}')
  s.extensions    = [ 'ext/kissfft/extconf.rb' ]
  s.require_paths = ["lib"]
end
