#require "bundler/gem_tasks"
require './lib/pcaprub/version.rb'

def java?
  /java/ === RUBY_PLATFORM
end

ENV['LANG'] = "en_US.UTF-8"


@gemspec = Gem::Specification.new do |spec|
  spec.name                  = "pcaprub"
  spec.version               = PCAPRUB::Pcap.version
  spec.authors               = ["shadowbq", "crondaemon", "jmcavinee", "unmarshal"]
  spec.email                 = "shadowbq@gmail.com"
  spec.description           = "libpcap bindings for Ruby 2.x"
  spec.summary               = "libpcap bindings for ruby"
  spec.homepage              = "https://github.com/pcaprub/pcaprub"
  spec.requirements          = "libpcap"
  spec.license               = "LGPL-2.1"
  spec.required_ruby_version = '~> 2.0'

  spec.files = [
    ".document",
    ".travis.yml",
    "FAQ.rdoc",
    "Gemfile",
    "LICENSE",
    "README.rdoc",
    "Rakefile",
    "USAGE.rdoc",
    "examples/dead_cap.rb",
    "examples/file_cap.rb",
    "examples/simple_cap.rb",
    "examples/telnet-raw.pcap",
    "ext/pcaprub_c/extconf.rb",
    "ext/pcaprub_c/pcaprub.c",
    "lib/pcaprub.rb",
    "lib/pcaprub/common.rb",
    "lib/pcaprub/ext.rb",
    "lib/pcaprub/version.rb",
    "test/test_helper.rb",
    "test/test_pcaprub_unit.rb"
  ]

  spec.extra_rdoc_files = [
    "FAQ.rdoc",
    "LICENSE",
    "README.rdoc",
    "USAGE.rdoc",
    "ext/pcaprub_c/pcaprub.c"
  ]
  spec.extensions = FileList["ext/**/extconf.rb"]
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake", '~> 0.9', '>= 0.9.2'
  spec.add_development_dependency "rake-compiler", '~> 0.6', '>= 0.6.0'
  spec.add_development_dependency "shoulda-context", '~> 1.1', '~> 1.1.6'
  spec.add_development_dependency "minitest", '~> 4.7', '>= 4.7.0'

end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.test_files = FileList['test/test_pcaprub_unit.rb']
  test.verbose = true
end

task :test

require 'rubygems/package_task'
Gem::PackageTask.new(@gemspec) do |pkg|
  pkg.need_zip = false
  pkg.need_tar = false
end

# prepend DevKit into compilation phase
if RUBY_PLATFORM =~ /mingw/
  task :compile => [:devkit]
  task :native  => [:devkit]
end

task :devkit do
  begin
    require "devkit"
  rescue LoadError => e
    abort "Failed to activate RubyInstaller's DevKit required for compilation."
  end
end

require 'rake/extensiontask'
Rake::ExtensionTask.new('pcaprub_c', @gemspec)

task :default => [:compile, :test]

require 'rdoc/task'
RDoc::Task.new do |rdoc|
  version = PCAPRUB::VERSION::STRING
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "pcaprub #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('FAQ*')
  rdoc.rdoc_files.include('LICENSE*')
  rdoc.rdoc_files.include('lib/**/*.rb')
  rdoc.rdoc_files.include('ext/**/*.c')
end

require 'rubygems/tasks'
Gem::Tasks.new

# Override standard release task
require 'git'
Rake::Task["release"].clear
desc 'Release the gem (create tag, build, publish)'
task :release do
  version = "#{PCAPRUB::VERSION::STRING}"
  remote = 'origin'
  puts "Creating tag v#{version}"
  git = Git.open(".")
  git.add_tag("v#{version}")
  puts "Pushing tag to #{remote}"
  git.push(remote, 'master', true)
  Rake::Task['clobber'].invoke
  Rake::Task['compile'].invoke
  Rake::Task['gem'].invoke
  gemtask = Gem::Tasks::Push.new
  gemtask.push("pkg/pcaprub-#{version}.gem")
end
