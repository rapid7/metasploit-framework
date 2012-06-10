require 'rubygems'

Gem::Specification.new do |gem|
  gem.name       = 'windows-api'
  gem.version    = '0.4.1'
  gem.author     = 'Daniel J. Berger'
  gem.license    = 'Artistic 2.0'
  gem.email      = 'djberg96@gmail.com'
  gem.homepage   = 'http://www.rubyforge.org/projects/win32utils'
  gem.summary    = 'An easier way to create methods using Win32::API'
  gem.test_files = Dir['test/test*.rb']
  gem.files      = Dir['**/*'].reject{ |f| f.include?('git') }

  gem.rubyforge_project = 'win32utils'
  gem.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST']

  gem.add_dependency('win32-api', '>= 1.4.5')

  gem.description = <<-EOF
    The windows-api library provides features over and above the basic
    interface provided by the win32-api library. Features included automatic
    constant generation, automatic defintion of ANSI and Unicode methods,
    special handling of functions that return a boolean value, and the
    ability to use native Windows type declarations.
  EOF
end
