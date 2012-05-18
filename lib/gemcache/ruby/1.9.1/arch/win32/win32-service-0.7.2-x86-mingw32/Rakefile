require 'rake'
require 'rake/clean'
require 'rake/testtask'
require 'rbconfig'
include Config

CLEAN.include(
  '**/*.gem',    # Gem files
  '**/*.rbc',    # Rubinius
  '**/*.o',      # C object file
  '**/*.log',    # Ruby extension build log
  '**/Makefile', # C Makefile
  "**/*.so",     # C shared object
  "**/*.lib",    # C build file
  "**/*.def",    # C build file
  "**/*.pdb",    # C build file
  "**/*.exp",    # C build file
  "**/*.obj",    # C build file
  "**/*.log",    # C build file
  "lib/win32/ruby18", "lib/win32/ruby19", "lib/win32/daemon.rb"
)

desc "Build the win32-service library"
task :build => [:clean] do
  make = CONFIG['host_os'] =~ /mingw|cygwin/i ? "make" : "nmake"

  Dir.chdir('ext') do
    ruby 'extconf.rb'
    sh "#{make}"
    FileUtils.cp('daemon.so', 'win32/daemon.so')      
  end  
end

namespace 'gem' do
  desc 'Build the gem'
  task :create => [:clean] do
    spec = eval(IO.read('win32-service.gemspec')) 
    Gem::Builder.new(spec).build
  end

  desc 'Install the gem'
  task :install => [:create] do
    file = Dir['*.gem'].first
    sh "gem install #{file}"
  end

  desc 'Build a binary gem'
  task :binary => [:build] do
    mkdir_p 'lib/win32'
    mv 'ext/win32/daemon.so', 'lib/win32/daemon.so'

    spec = eval(IO.read('win32-service.gemspec'))
    spec.extensions = nil
    spec.platform = Gem::Platform::CURRENT

    spec.files = spec.files.reject{ |f| f.include?('ext') }

    Gem::Builder.new(spec).build
  end

  # This is for me, not for you.
  desc 'Create a gem with binaries for 1.8 and 1.9'
  task :binaries => [:clean] do
    make = CONFIG['host_os'] =~ /mingw|cygwin/i ? "make" : "nmake"

    mkdir_p "lib/win32/ruby18"
    mkdir_p "lib/win32/ruby19"

    Dir.chdir('ext') do
      # Ruby 1.8
      sh "C:\\ruby187\\bin\\ruby extconf.rb"
      sh "#{make}"
      mv 'daemon.so', '../lib/win32/ruby18'
      sh "#{make} distclean"

      # Ruby 1.9
      sh "C:\\ruby192\\bin\\ruby extconf.rb"
      sh "#{make}"
      mv 'daemon.so', '../lib/win32/ruby19'
    end

    File.open("lib/win32/daemon.rb", "w"){ |fh|
      fh.puts "if RUBY_VERSION.to_f >= 1.9"
      fh.puts "  require 'win32/ruby19/daemon'"
      fh.puts "else"
      fh.puts "  require 'win32/ruby18/daemon'"
      fh.puts "end"
    }

    spec = eval(IO.read('win32-service.gemspec'))
    spec.extensions = nil
    spec.platform = Gem::Platform::CURRENT

    spec.files = spec.files.reject{ |f| f.include?('ext') }

    spec.files += [
      'lib/win32/daemon.rb',
      'lib/win32/ruby18/daemon.so',
      'lib/win32/ruby19/daemon.so'
    ]

    Gem::Builder.new(spec).build
  end
end

namespace :example do
  desc "Run the services example program."
  task :services do
    sh "ruby -Ilib examples/demo_services.rb"
  end
end

namespace 'test' do
  desc 'Run all tests for the win32-service library'
  Rake::TestTask.new('all') do |t|
    task :all => :build
    t.libs << 'ext'
    t.verbose = true
    t.warning = true
  end

  desc 'Run the tests for the Win32::Daemon class'
  Rake::TestTask.new('daemon') do |t|
    task :daemon => :build
    t.libs << 'ext'
    t.verbose = true
    t.warning = true
    t.test_files = FileList['test/test_win32_daemon.rb']
  end

  namespace 'service' do
    desc 'Run the tests for the Win32::Service class'
    Rake::TestTask.new('all') do |t|
      t.verbose = true
      t.warning = true
      t.test_files = FileList['test/test_win32_service*.rb']
    end

    Rake::TestTask.new('configure') do |t|
      t.verbose = true
      t.warning = true
      t.test_files = FileList['test/test_win32_service_configure.rb']
    end

    Rake::TestTask.new('control') do |t|
      t.verbose = true
      t.warning = true
      t.test_files = FileList['test/test_win32_service.rb']
    end

    Rake::TestTask.new('create') do |t|
      t.verbose = true
      t.warning = true
      t.test_files = FileList['test/test_win32_service_create.rb']
    end

    Rake::TestTask.new('info') do |t|
      t.verbose = true
      t.warning = true
      t.test_files = FileList['test/test_win32_service_info.rb']
    end

    Rake::TestTask.new('status') do |t|
      t.verbose = true
      t.warning = true
      t.test_files = FileList['test/test_win32_service_status.rb']
    end
  end

  task :all do
    Rake.application[:clean].execute
  end

  task :daemon do
    Rake.application[:clean].execute
  end
end

task :default => 'test:all'
