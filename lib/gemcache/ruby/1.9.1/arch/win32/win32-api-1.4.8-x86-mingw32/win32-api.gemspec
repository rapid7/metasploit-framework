require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-api'
  spec.version    = '1.4.8'
  spec.authors    = ['Daniel J. Berger', 'Park Heesob']
  spec.license    = 'Artistic 2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'http://www.rubyforge.org/projects/win32utils'
  spec.platform   = Gem::Platform::RUBY
  spec.summary    = 'A superior replacement for Win32API'
  spec.has_rdoc   = true
  spec.test_files = Dir['test/test*']
  spec.extensions = ['ext/extconf.rb']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') }

  spec.rubyforge_project = 'win32utils'
  spec.required_ruby_version = '>= 1.8.2'
  spec.extra_rdoc_files = ['README', 'CHANGES', 'MANIFEST', 'ext/win32/api.c']

  spec.add_development_dependency('test-unit', '>= 2.1.2')

  spec.description = <<-EOF
    The Win32::API library is meant as a replacement for the Win32API
    library that ships as part of the standard library. It contains several
    advantages over Win32API, including callback support, raw function
    pointers, an additional string type, and more.
  EOF
end
