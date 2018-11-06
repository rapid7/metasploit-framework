require 'rake/testtask'
require 'rubygems/package_task'
require 'rake/extensiontask'
require 'rake/clean'
require 'rdoc/task'
require 'benchmark'

CLEAN.include(
  "tmp",
  "lib/2.0",
  "lib/2.1",
  "lib/bcrypt_pbkdf_ext.so"
)
CLOBBER.include(
  "doc",
  "pkg"
)

task 'gem:windows' do
  require 'rake_compiler_dock'
  RakeCompilerDock.sh "bundle && rake cross native gem RUBY_CC_VERSION=2.3.0:2.2.2:2.1.6:2.0.0"
end

GEMSPEC = Gem::Specification.load("bcrypt_pbkdf.gemspec")

task :default => [:compile, :spec]

desc "Run all tests"
Rake::TestTask.new do |t|
  #t.pattern = 
  t.test_files = FileList['test/**/*_test.rb']
  t.ruby_opts = ['-w']
  t.libs << "test"
  t.verbose = true
end
task :spec => :test

desc 'Generate RDoc'
RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.options += GEMSPEC.rdoc_options
  rdoc.template = ENV['TEMPLATE'] if ENV['TEMPLATE']
  rdoc.rdoc_files.include(*GEMSPEC.extra_rdoc_files)
end

Gem::PackageTask.new(GEMSPEC) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
end

Rake::ExtensionTask.new("bcrypt_pbkdf_ext", GEMSPEC) do |ext|
  ext.ext_dir = 'ext/mri'
  ext.cross_compile = true
  ext.cross_platform = ['x86-mingw32', 'x64-mingw32']
end
