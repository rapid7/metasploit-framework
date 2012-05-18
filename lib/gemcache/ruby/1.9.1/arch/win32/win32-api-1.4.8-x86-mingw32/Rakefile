require 'rake'
require 'rake/clean'
require 'rake/testtask'
require 'rbconfig'
include Config

CLEAN.include(
  '**/*.gem',               # Gem files
  '**/*.rbc',               # Rubinius
  '**/*.o',                 # C object file
  '**/*.log',               # Ruby extension build log
  '**/Makefile',            # C Makefile
  '**/*.def',               # Definition files
  '**/*.exp',
  '**/*.lib',
  '**/*.pdb',
  '**/*.obj',
  '**/*.stackdump',         # Junk that can happen on Windows
  "**/*.#{CONFIG['DLEXT']}" # C shared object
)

CLOBBER.include('lib') # Generated when building binaries

make = CONFIG['host_os'] =~ /mingw|cygwin/i ? 'make' : 'nmake'

desc 'Build the ruby.exe.manifest if it does not already exist'
task :build_manifest do
  version = CONFIG['host_os'].split('_')[1]

  if version && version.to_i >= 80
    unless File.exist?(File.join(CONFIG['bindir'], 'ruby.exe.manifest'))
      Dir.chdir(CONFIG['bindir']) do
        sh "mt -inputresource:ruby.exe;2 -out:ruby.exe.manifest"
      end
    end
  end
end

desc "Build the win32-api library"
task :build => [:clean, :build_manifest] do
  Dir.chdir('ext') do
    ruby "extconf.rb"
    sh make
    cp 'api.so', 'win32' # For testing
  end
end

namespace 'gem' do
  desc 'Build the win32-api gem'
  task :create => [:clean] do
    spec = eval(IO.read('win32-api.gemspec'))
    Gem::Builder.new(spec).build
  end

  desc 'Build a binary gem'
  task :binary, :ruby18, :ruby19 do |task, args|
    args.with_defaults(
      :ruby18 => "c:/ruby/bin/ruby",
      :ruby19 => "c:/ruby19/bin/ruby"
    )

    Rake::Task[:clobber].invoke
    mkdir_p 'lib/win32/ruby18/win32'
    mkdir_p 'lib/win32/ruby19/win32'

    args.each{ |key, rubyx|
      Dir.chdir('ext') do
        sh "make distclean" rescue nil
        sh "#{rubyx} extconf.rb"
        sh "make"
        if key.to_s == 'ruby18'
          cp 'api.so', '../lib/win32/ruby18/win32/api.so'
        else
          cp 'api.so', '../lib/win32/ruby19/win32/api.so'
        end
      end
    }

    # Create a stub file that automatically require's the correct binary
    File.open('lib/win32/api.rb', 'w'){ |fh|
      fh.puts "if RUBY_VERSION.to_f >= 1.9"
      fh.puts "  require File.join(File.dirname(__FILE__), 'ruby19/win32/api')"
      fh.puts "else"
      fh.puts "  require File.join(File.dirname(__FILE__), 'ruby18/win32/api')"
      fh.puts "end"
    }

    spec = eval(IO.read('win32-api.gemspec'))
    spec.platform = Gem::Platform::CURRENT
    spec.extensions = nil
    spec.files = spec.files.reject{ |f| f.include?('ext') }

    Gem::Builder.new(spec).build
  end

  desc 'Install the gem'
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file}"
  end
end

namespace 'test' do
  Rake::TestTask.new(:all) do |test|
    task :all => [:build]
    test.libs << 'ext'
    test.warning = true
    test.verbose = true
  end

  Rake::TestTask.new(:callback) do |test|
    task :callback => [:build]
    test.test_files = FileList['test/test_win32_api_callback.rb']
    test.libs << 'ext'
    test.warning = true
    test.verbose = true
  end

  Rake::TestTask.new(:function) do |test|
    task :function => [:build]
    test.test_files = FileList['test/test_win32_api_function.rb']
    test.libs << 'ext'
    test.warning = true
    test.verbose = true
  end
end

task :default => 'test:all'
