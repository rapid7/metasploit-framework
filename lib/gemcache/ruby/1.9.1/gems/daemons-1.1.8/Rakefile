require 'rubygems'
#Gem::manage_gems

require 'rake/gempackagetask'
#require 'rake/testtask'
require 'rake/packagetask'
require 'rake/rdoctask'

$LOAD_PATH << './lib'
require 'daemons'


PKG_NAME = "daemons"

PKG_FILES = FileList[
  "Rakefile", "Releases", "TODO", "README", "LICENSE",
  "setup.rb",
  "lib/**/*.rb",
  #"test/**/*",
  "examples/**/*.rb"
]
#PKG_FILES.exclude(%r(^test/tmp/.+))
PKG_FILES.exclude(%r(\.pid$))
PKG_FILES.exclude(%r(\.log$))
PKG_FILES.exclude(%r(\.output$))
PKG_FILES.exclude(%r(\.txt$))

spec = Gem::Specification.new do |s|
  s.name = PKG_NAME
  s.version = Daemons::VERSION
  s.author = "Thomas Uehlinger"
  s.email = "th.uehlinger@gmx.ch"
  s.rubyforge_project = "daemons"
  s.homepage = "http://daemons.rubyforge.org"
  s.platform  = Gem::Platform::RUBY
  s.summary = "A toolkit to create and control daemons in different ways"
  s.description = <<-EOF
    Daemons provides an easy way to wrap existing ruby scripts (for example a self-written server) 
    to be run as a daemon and to be controlled by simple start/stop/restart commands.
    
    You can also call blocks as daemons and control them from the parent or just daemonize the current
    process.
    
    Besides this basic functionality, daemons offers many advanced features like exception 
    backtracing and logging (in case your ruby script crashes) and monitoring and automatic
    restarting of your processes if they crash.
  EOF
    
  #s.files = FileList["{test,lib}/**/*"].exclude("rdoc").to_a
  s.files = PKG_FILES
  s.require_path = "lib"
  s.autorequire = "daemons"
  s.has_rdoc = true
  s.extra_rdoc_files = ["README", "Releases", "TODO"]
end

Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end


#Rake::PackageTask.new("package") do |p|
#  p.name = PKG_NAME
#  p.version = Daemons::VERSION
#  p.need_tar = true
#  p.need_zip = true
#  p.package_files = PKG_FILES
#end

 
task :default => [:package]

desc 'Show information about the gem.'
task :debug_gem do
  puts spec.to_ruby
end

task :upload do
  sh "scp -r html/* uehli@rubyforge.org:/var/www/gforge-projects/daemons"
end


desc "Create the RDOC html files"
rd = Rake::RDocTask.new("rdoc") { |rdoc|
  rdoc.rdoc_dir = 'html'
  rdoc.title    = "Daemons"
  rdoc.options << '--line-numbers' << '--inline-source' << '--main' << 'README'
  rdoc.rdoc_files.include('README', 'TODO', 'Releases')
  rdoc.rdoc_files.include('lib/**/*.rb')
}
