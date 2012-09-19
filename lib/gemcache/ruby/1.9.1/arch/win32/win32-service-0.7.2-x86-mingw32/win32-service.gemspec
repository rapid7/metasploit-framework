require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-service'
  spec.version    = '0.7.2'
  spec.authors    = ['Daniel J. Berger', 'Park Heesob']
  spec.license    = 'Artistic 2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'http://www.rubyforge.org/projects/win32utils'
  spec.platform   = Gem::Platform::RUBY
  spec.summary    = 'An interface for MS Windows services'
  spec.test_files = Dir['test/test*.rb']
  spec.extensions = ['ext/extconf.rb']
   
  spec.files = Dir['**/*'].reject{ |f| f.include?('git') }

  spec.extra_rdoc_files = [
    'CHANGES',
    'README',
    'MANIFEST',
    'doc/service.txt',
    'doc/daemon.txt',
    'ext/win32/daemon.c'
  ]

  spec.rubyforge_project = 'win32utils'
  spec.required_ruby_version = '>= 1.8.2'

  spec.add_dependency('windows-pr', '>= 1.0.8')
  spec.add_development_dependency('test-unit', '>= 2.1.0')

  spec.description = <<-EOF
    The win32-service library provides a Ruby interface to services on
    MS Windows. You can create new services, or control, configure and
    inspect existing services.

    In addition, you can create a pure Ruby service by using the Daemon
    class that is included as part of the library.
  EOF
end
