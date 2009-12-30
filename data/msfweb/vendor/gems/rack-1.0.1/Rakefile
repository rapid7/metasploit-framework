# Rakefile for Rack.  -*-ruby-*-
require 'rake/rdoctask'
require 'rake/testtask'


desc "Run all the tests"
task :default => [:test]


desc "Make an archive as .tar.gz"
task :dist => [:chmod, :changelog, :rdoc, "SPEC", "rack.gemspec"] do
  FileUtils.touch("RDOX")
  sh "git archive --format=tar --prefix=#{release}/ HEAD^{tree} >#{release}.tar"
  sh "pax -waf #{release}.tar -s ':^:#{release}/:' RDOX SPEC ChangeLog doc rack.gemspec"
  sh "gzip -f -9 #{release}.tar"
end

desc "Make an official release"
task :officialrelease do
  puts "Official build for #{release}..."
  sh "rm -rf stage"
  sh "git clone --shared . stage"
  sh "cd stage && rake officialrelease_really"
  sh "mv stage/#{release}.tar.gz stage/#{release}.gem ."
end

task :officialrelease_really => [:fulltest, "RDOX", "SPEC", :dist, :gem] do
  sh "sha1sum #{release}.tar.gz #{release}.gem"
end


def version
  abort "You need to pass VERSION=... to build packages."  unless ENV["VERSION"]
  ENV["VERSION"]
end

def release
  "rack-#{version}"
end

def manifest
  `git ls-files`.split("\n")
end


desc "Make binaries executable"
task :chmod do
  Dir["bin/*"].each { |binary| File.chmod(0775, binary) }
  Dir["test/cgi/test*"].each { |binary| File.chmod(0775, binary) }
end

desc "Generate a ChangeLog"
task :changelog do
  File.open("ChangeLog", "w") { |out|
    `git log -z`.split("\0").map { |chunk|
      author = chunk[/Author: (.*)/, 1].strip
      date = chunk[/Date: (.*)/, 1].strip
      desc, detail = $'.strip.split("\n", 2)
      detail ||= ""
      detail = detail.gsub(/.*darcs-hash:.*/, '')
      detail.rstrip!
      out.puts "#{date}  #{author}"
      out.puts "  * #{desc.strip}"
      out.puts detail  unless detail.empty?
      out.puts
    }
  }
end


desc "Generate RDox"
task "RDOX" do
  sh "specrb -Ilib:test -a --rdox >RDOX"
end

desc "Generate Rack Specification"
task "SPEC" do
  File.open("SPEC", "wb") { |file|
    IO.foreach("lib/rack/lint.rb") { |line|
      if line =~ /## (.*)/
        file.puts $1
      end
    }
  }
end

desc "Run all the fast tests"
task :test do
  sh "specrb -Ilib:test -w #{ENV['TEST'] || '-a'} #{ENV['TESTOPTS'] || '-t "^(?!Rack::Handler|Rack::Adapter|Rack::Session::Memcache|Rack::Auth::OpenID)"'}"
end

desc "Run all the tests"
task :fulltest => [:chmod] do
  sh "specrb -Ilib:test -w #{ENV['TEST'] || '-a'} #{ENV['TESTOPTS']}"
end

begin
  require 'rubygems'
rescue LoadError
  # Too bad.
else
  task "rack.gemspec" do
    spec = Gem::Specification.new do |s|
      s.name            = "rack"
      s.version         = version
      s.platform        = Gem::Platform::RUBY
      s.summary         = "a modular Ruby webserver interface"
      
      s.description = <<-EOF
Rack provides minimal, modular and adaptable interface for developing
web applications in Ruby.  By wrapping HTTP requests and responses in
the simplest way possible, it unifies and distills the API for web
servers, web frameworks, and software in between (the so-called
middleware) into a single method call.

Also see http://rack.rubyforge.org.
    EOF

      s.files           = manifest + %w(SPEC RDOX rack.gemspec)
      s.bindir          = 'bin'
      s.executables     << 'rackup'
      s.require_path    = 'lib'
      s.has_rdoc        = true
      s.extra_rdoc_files = ['README', 'SPEC', 'RDOX', 'KNOWN-ISSUES']
      s.test_files      = Dir['test/{test,spec}_*.rb']
      
      s.author          = 'Christian Neukirchen'
      s.email           = 'chneukirchen@gmail.com'
      s.homepage        = 'http://rack.rubyforge.org'
      s.rubyforge_project = 'rack'
      
      s.add_development_dependency 'test-spec'
      
      s.add_development_dependency 'camping'
      s.add_development_dependency 'fcgi'
      s.add_development_dependency 'memcache-client'
      s.add_development_dependency 'mongrel'
      s.add_development_dependency 'ruby-openid', '~> 2.0.0'
      s.add_development_dependency 'thin'
    end

    File.open("rack.gemspec", "w") { |f| f << spec.to_ruby }
  end

  task :gem => ["rack.gemspec", "SPEC"] do
    FileUtils.touch("RDOX")
    sh "gem build rack.gemspec"
  end
end

desc "Generate RDoc documentation"
task :rdoc do
  sh(*%w{rdoc --line-numbers --main README 
              --title 'Rack\ Documentation' --charset utf-8 -U -o doc} +
              %w{README KNOWN-ISSUES SPEC RDOX} +
              Dir["lib/**/*.rb"])
end

task :pushsite => [:rdoc] do
  sh "cd site && git gc"
  sh "rsync -avz doc/ chneukirchen@rack.rubyforge.org:/var/www/gforge-projects/rack/doc/"
  sh "rsync -avz site/ chneukirchen@rack.rubyforge.org:/var/www/gforge-projects/rack/"
  sh "cd site && git push"
end
