Gem::Specification.new do |s|
  s.name            = "rack"
  s.version         = "1.4.1"
  s.platform        = Gem::Platform::RUBY
  s.summary         = "a modular Ruby webserver interface"

  s.description = <<-EOF
Rack provides a minimal, modular and adaptable interface for developing
web applications in Ruby.  By wrapping HTTP requests and responses in
the simplest way possible, it unifies and distills the API for web
servers, web frameworks, and software in between (the so-called
middleware) into a single method call.

Also see http://rack.rubyforge.org.
EOF

  s.files           = Dir['{bin/*,contrib/*,example/*,lib/**/*,test/**/*}'] +
                        %w(COPYING KNOWN-ISSUES rack.gemspec Rakefile README.rdoc SPEC)
  s.bindir          = 'bin'
  s.executables     << 'rackup'
  s.require_path    = 'lib'
  s.extra_rdoc_files = ['README.rdoc', 'KNOWN-ISSUES']
  s.test_files      = Dir['test/spec_*.rb']

  s.author          = 'Christian Neukirchen'
  s.email           = 'chneukirchen@gmail.com'
  s.homepage        = 'http://rack.rubyforge.org'
  s.rubyforge_project = 'rack'

  s.add_development_dependency 'bacon'
  s.add_development_dependency 'rake'

  s.add_development_dependency 'ruby-fcgi'
  s.add_development_dependency 'memcache-client'
  s.add_development_dependency 'mongrel', '>= 1.2.0.pre2'
  s.add_development_dependency 'thin'
end
