#!/usr/bin/env rake

require 'rbconfig'
require 'pathname'
require 'tmpdir'

begin
	require 'rake/extensiontask'
rescue LoadError
	abort "This Rakefile requires rake-compiler (gem install rake-compiler)"
end

begin
	require 'hoe'
rescue LoadError
	abort "This Rakefile requires hoe (gem install hoe)"
end

require 'rake/clean'

# Build directory constants
BASEDIR = Pathname( __FILE__ ).dirname
SPECDIR = BASEDIR + 'spec'
LIBDIR  = BASEDIR + 'lib'
EXTDIR  = BASEDIR + 'ext'
PKGDIR  = BASEDIR + 'pkg'
TMPDIR  = BASEDIR + 'tmp'

DLEXT   = Config::CONFIG['DLEXT']
EXT     = LIBDIR + "pg_ext.#{DLEXT}"

TEST_DIRECTORY = BASEDIR + "tmp_test_specs"

CLOBBER.include( TEST_DIRECTORY.to_s )
CLEAN.include( PKGDIR.to_s, TMPDIR.to_s )

# Set up Hoe plugins
Hoe.plugin :mercurial
Hoe.plugin :signing

Hoe.plugins.delete :rubyforge
Hoe.plugins.delete :compiler

load 'Rakefile.cross'


# Hoe specification
$hoespec = Hoe.spec 'pg' do
	self.readme_file = 'README.rdoc'
	self.history_file = 'History.rdoc'
	self.extra_rdoc_files = Rake::FileList[ '*.rdoc' ]
	self.extra_rdoc_files.include( 'POSTGRES', 'LICENSE' )
	self.extra_rdoc_files.include( 'ext/*.c' )

	self.developer 'Michael Granger', 'ged@FaerieMUD.org'

	self.dependency 'rake-compiler', '~> 0.7', :developer
	self.dependency	'rspec', '~> 2.6', :developer

	self.spec_extras[:licenses] = ['BSD', 'Ruby', 'GPL']
	self.spec_extras[:extensions] = [ 'ext/extconf.rb' ]

	self.require_ruby_version( '>= 1.8.7' )

	self.hg_sign_tags = true if self.respond_to?( :hg_sign_tags= )
	self.check_history_on_release = true if self.respond_to?( :check_history_on_release= )

	self.rdoc_locations << "deveiate:/usr/local/www/public/code/#{remote_rdoc_dir}"
end

ENV['VERSION'] ||= $hoespec.spec.version.to_s

# Tests should pass before checking in
task 'hg:precheckin' => [ :check_history, :check_manifest, :spec ]

# Support for 'rvm specs'
task :specs => :spec

# Compile before testing
task :spec => :compile

# gem-testers support
task :test do
	# rake-compiler always wants to copy the compiled extension into lib/, but
	# we don't want testers to have to re-compile, especially since that
	# often fails because they can't (and shouldn't have to) write to tmp/ in
	# the installed gem dir. So we clear the task rake-compiler set up
	# to break the dependency between :spec and :compile when running under
	# rubygems-test, and then run :spec.
	Rake::Task[ EXT.to_s ].clear
	Rake::Task[ :spec ].execute
end

desc "Turn on warnings and debugging in the build."
task :maint do
	ENV['MAINTAINER_MODE'] = 'yes'
end

ENV['RUBY_CC_VERSION'] ||= '1.8.7:1.9.2'

# Rake-compiler task
Rake::ExtensionTask.new do |ext|
	ext.name           = 'pg_ext'
	ext.gem_spec       = $hoespec.spec
	ext.ext_dir        = 'ext'
	ext.lib_dir        = 'lib'
	ext.source_pattern = "*.{c,h}"
	ext.cross_compile  = true
	ext.cross_platform = %w[i386-mingw32]

	# configure options only for cross compile
	ext.cross_config_options += [
		"--with-pg-include=#{STATIC_POSTGRESQL_LIBDIR}",
		"--with-opt-include=#{STATIC_POSTGRESQL_INCDIR}",
		"--with-pg-lib=#{STATIC_POSTGRESQL_LIBDIR}",
		"--with-opt-lib=#{STATIC_OPENSSL_BUILDDIR}",
	]
end


# Make the ChangeLog update if the repo has changed since it was last built
file '.hg/branch' do
	abort "You need the Mercurial repo to make packages"
end
file 'ChangeLog' => '.hg/branch' do |task|
	$stderr.puts "Updating the changelog..."
	begin
		content = make_changelog()
	rescue NameError
		abort "Packaging tasks require the hoe-mercurial plugin (gem install hoe-mercurial)"
	end
	File.open( task.name, 'w', 0644 ) do |fh|
		fh.print( content )
	end
end

# Rebuild the ChangeLog immediately before release
task :prerelease => 'ChangeLog'


desc "Stop any Postmaster instances that remain after testing."
task :cleanup_testing_dbs do
    require 'spec/lib/helpers'
    PgTestingHelpers.stop_existing_postmasters()
    Rake::Task[:clean].invoke
end

