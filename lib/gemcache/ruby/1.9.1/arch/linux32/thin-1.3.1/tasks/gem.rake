require 'rake/gempackagetask'
require 'yaml'

task :clean => :clobber_package

Thin::GemSpec = Gem::Specification.new do |s|
  s.name                  = Thin::NAME
  s.version               = Thin::VERSION::STRING
  s.platform              = WIN ? Gem::Platform::CURRENT : Gem::Platform::RUBY
  s.summary               = 
  s.description           = "A thin and fast web server"
  s.author                = "Marc-Andre Cournoyer"
  s.email                 = 'macournoyer@gmail.com'
  s.homepage              = 'http://code.macournoyer.com/thin/'
  s.rubyforge_project     = 'thin'
  s.executables           = %w(thin)

  s.required_ruby_version = '>= 1.8.5'
  
  s.add_dependency        'rack',         '>= 1.0.0'
  s.add_dependency        'eventmachine', '>= 0.12.6'
  unless WIN
    s.add_dependency      'daemons',      '>= 1.0.9'
  end

  s.files                 = %w(CHANGELOG README Rakefile) +
                            Dir.glob("{benchmark,bin,doc,example,lib,spec,tasks}/**/*") - Dir.glob("lib/thin_parser.*") + 
                            Dir.glob("ext/**/*.{h,c,rb,rl}")
  
  if WIN
    s.files              += FileList["lib/*/thin_parser.*"].to_a
  else
    s.extensions          = FileList["ext/**/extconf.rb"].to_a
  end
  
  s.require_path          = "lib"
  s.bindir                = "bin"
end

Rake::GemPackageTask.new(Thin::GemSpec) do |p|
  p.gem_spec = Thin::GemSpec
end

task :tag_warn do
  puts "*" * 40
  puts "Don't forget to tag the release:"
  puts
  puts "  git tag -m 'Tagging #{Thin::SERVER}' -a v#{Thin::VERSION::STRING}"
  puts
  puts "or run rake tag"
  puts "*" * 40
end
task :tag do
  sh "git tag -m 'Tagging #{Thin::SERVER}' -a v#{Thin::VERSION::STRING}"
end
task :gem => :tag_warn

namespace :gem do
  desc 'Upload gems to gemcutter.org'
  task :push do
    Dir["pkg/#{Thin::GemSpec.full_name}*.gem"].each do |file|
      sh "gem push #{file}"
    end
  end
end
