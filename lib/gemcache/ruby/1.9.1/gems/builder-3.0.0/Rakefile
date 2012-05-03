# Rakefile for rake        -*- ruby -*-

# Copyright 2004, 2005, 2006 by Jim Weirich (jim@weirichhouse.org).
# All rights reserved.

# Permission is granted for use, copying, modification, distribution,
# and distribution of modified versions of this work as long as the
# above copyright notice is included.

require 'rake/clean'
require 'rake/testtask'
require 'rake/rdoctask'
begin
  require 'rubygems'
  require 'rake/gempackagetask'
rescue Exception
  nil
end

# Determine the current version of the software

CLOBBER.include('pkg')

CURRENT_VERSION = '3.0.0'
PKG_VERSION = ENV['REL'] ? ENV['REL'] : CURRENT_VERSION

SRC_RB = FileList['lib/**/*.rb']

# The default task is run if rake is given no explicit arguments.

desc "Default Task"
task :default => :test_all

# Test Tasks ---------------------------------------------------------

desc "Run all tests"
task :test_all => [:test_units]
task :ta => [:test_all]

task :tu => [:test_units]

Rake::TestTask.new("test_units") do |t|
  t.test_files = FileList['test/test*.rb']
  t.libs << "."
  t.verbose = false
end

# Create a task to build the RDOC documentation tree.

rd = Rake::RDocTask.new("rdoc") { |rdoc|
  rdoc.rdoc_dir = 'html'
  rdoc.title    = "Builder for Markup"
  rdoc.options << '--line-numbers' << '--inline-source' << '--main' << 'README.rdoc'
  rdoc.rdoc_files.include('lib/**/*.rb', '[A-Z]*', 'doc/**/*.rdoc')
  rdoc.template = 'doc/jamis.rb'
}

# ====================================================================
# Create a task that will package the Rake software into distributable
# gem files.

PKG_FILES = FileList[
  'lib/**/*.rb',
  'test/**/*.rb',
  'scripts/**/*.rb'
]
PKG_FILES.exclude('test/testcssbuilder.rb')
PKG_FILES.exclude('lib/builder/css.rb')

BLANKSLATE_FILES = FileList[
  'lib/blankslate.rb',
  'test/test_blankslate.rb'
]

if ! defined?(Gem)
  puts "Package Target requires RubyGEMs"
else
  spec = Gem::Specification.new do |s|

    #### Basic information.

    s.name = 'builder'
    s.version = PKG_VERSION
    s.summary = "Builders for MarkUp."
    s.description = %{\
Builder provides a number of builder objects that make creating structured data
simple to do.  Currently the following builder objects are supported:

* XML Markup
* XML Events
}

    s.files = PKG_FILES.to_a
    s.require_path = 'lib'
    s.autorequire = 'builder'

    s.test_files = PKG_FILES.select { |fn| fn =~ /^test\/test/ }

    s.has_rdoc = true
    s.extra_rdoc_files = rd.rdoc_files.reject { |fn| fn =~ /\.rb$/ }.to_a
    s.rdoc_options <<
      '--title' <<  'Builder -- Easy XML Building' <<
      '--main' << 'README.rdoc' <<
      '--line-numbers'

    s.author = "Jim Weirich"
    s.email = "jim@weirichhouse.org"
    s.homepage = "http://onestepback.org"
  end

  blankslate_spec = Gem::Specification.new do |s|

    #### Basic information.

    s.name = 'blankslate'
    s.version = PKG_VERSION
    s.summary = "Blank Slate base class."
    s.description = %{\
BlankSlate provides a base class where almost all of the methods from Object and
Kernel have been removed.  This is useful when providing proxy object and other
classes that make heavy use of method_missing.
}

    s.files = BLANKSLATE_FILES.to_a
    s.require_path = 'lib'
    s.autorequire = 'builder'

    s.test_files = PKG_FILES.select { |fn| fn =~ /^test\/test/ }

    s.has_rdoc = true
    s.extra_rdoc_files = rd.rdoc_files.reject { |fn| fn =~ /\.rb$/ }.to_a
    s.rdoc_options <<
      '--title' <<  'BlankSlate -- Base Class for building proxies.' <<
      '--main' << 'README.rdoc' <<
      '--line-numbers'

    s.author = "Jim Weirich"
    s.email = "jim@weirichhouse.org"
    s.homepage = "http://onestepback.org"
  end

  namespace 'builder' do
    Rake::GemPackageTask.new(spec) do |t|
      t.need_tar = true
    end
  end

  namespace 'blankslate' do
    Rake::GemPackageTask.new(blankslate_spec) do |t|
      t.need_tar = true
    end
  end

  task :package => ['builder:package', 'blankslate:package']
end

desc "Look for Debugging print lines"
task :dbg do
  FileList['**/*.rb'].egrep /\bDBG|\bbreakpoint\b/
end


# RCov ---------------------------------------------------------------
begin
  require 'rcov/rcovtask'

  Rcov::RcovTask.new do |t|
    t.libs << "test"
    t.rcov_opts = [
      '-xRakefile', '--text-report'
    ]
    t.test_files = FileList[
      'test/test*.rb'
    ]
    t.output_dir = 'coverage'
    t.verbose = true
  end
rescue LoadError
  # No rcov available
end

# Tags file ----------------------------------------------------------

namespace "tags" do
  desc "Create a TAGS file"
  task :emacs => "TAGS"

  TAGS = 'xctags -e'

  file "TAGS" => SRC_RB do
    puts "Makings TAGS"
    sh "#{TAGS} #{SRC_RB}", :verbose => false
  end
end

# --------------------------------------------------------------------
# Creating a release

def announce(msg='')
  STDERR.puts msg
end

desc "Make a new release"
task :release => [
  :prerelease,
  :clobber,
  :test_all,
  :update_version,
  :package,
  :tag] do

  announce
  announce "**************************************************************"
  announce "* Release #{PKG_VERSION} Complete."
  announce "* Packages ready to upload."
  announce "**************************************************************"
  announce
end

# Validate that everything is ready to go for a release.
task :prerelease do
  announce
  announce "**************************************************************"
  announce "* Making RubyGem Release #{PKG_VERSION}"
  announce "* (current version #{CURRENT_VERSION})"
  announce "**************************************************************"
  announce

  # Is a release number supplied?
  unless ENV['REL']
    fail "Usage: rake release REL=x.y.z [REUSE=tag_suffix]"
  end

  # Is the release different than the current release.
  # (or is REUSE set?)
  if PKG_VERSION == CURRENT_VERSION && ! ENV['REUSE']
    fail "Current version is #{PKG_VERSION}, must specify REUSE=tag_suffix to reuse version"
  end

  # Are all source files checked in?
  if ENV['RELTEST']
    announce "Release Task Testing, skipping checked-in file test"
  else
    announce "Checking for unchecked-in files..."
    data = `cvs -q update`
    unless data =~ /^$/
      fail "CVS update is not clean ... do you have unchecked-in files?"
    end
    announce "No outstanding checkins found ... OK"
  end
end

task :update_version => [:prerelease] do
  if PKG_VERSION == CURRENT_VERSION
    announce "No version change ... skipping version update"
  else
    announce "Updating Builder version to #{PKG_VERSION}"
    open("Rakefile") do |rakein|
      open("Rakefile.new", "w") do |rakeout|
	rakein.each do |line|
	  if line =~ /^CURRENT_VERSION\s*=\s*/
	    rakeout.puts "CURRENT_VERSION = '#{PKG_VERSION}'"
	  else
	    rakeout.puts line
	  end
	end
      end
    end
    mv "Rakefile.new", "Rakefile"
    if ENV['RELTEST']
      announce "Release Task Testing, skipping commiting of new version"
    else
      sh "cvs commit -m \"Updated to version #{PKG_VERSION}\" Rakefile"
    end
  end
end

desc "Tag all the CVS files with the latest release number (REL=x.y.z)"
task :tag => [:prerelease] do
  reltag = "REL_#{PKG_VERSION.gsub(/\./, '_')}"
  reltag << ENV['REUSE'].gsub(/\./, '_') if ENV['REUSE']
  announce "Tagging CVS with [#{reltag}]"
  if ENV['RELTEST']
    announce "Release Task Testing, skipping CVS tagging"
  else
    sh %{cvs tag #{reltag}}
  end
end

desc "Install the jamis RDoc template"
task :install_jamis_template do
  require 'rbconfig'
  dest_dir = File.join(Config::CONFIG['rubylibdir'], "rdoc/generators/template/html")
  fail "Unabled to write to #{dest_dir}" unless File.writable?(dest_dir)
  install "doc/jamis.rb", dest_dir, :verbose => true
end
