#!/usr/bin/env ruby

begin
	require 'pg_ext'
rescue LoadError
	# If it's a Windows binary gem, try the <major>.<minor> subdirectory
	if RUBY_PLATFORM =~/(mswin|mingw)/i
		major_minor = RUBY_VERSION[ /^(\d+\.\d+)/ ] or
			raise "Oops, can't extract the major/minor version from #{RUBY_VERSION.dump}"

		add_dll_path = proc do |path, &block|
			begin
				require 'ruby_installer'
				RubyInstaller.add_dll_directory(path, &block)
			rescue LoadError
				old_path = ENV['PATH']
				ENV['PATH'] = "#{path};#{old_path}"
				block.call
				ENV['PATH'] = old_path
			end
		end

		# Temporary add this directory for DLL search, so that libpq.dll can be found.
		add_dll_path.call(__dir__) do
			require "#{major_minor}/pg_ext"
		end
	else
		raise
	end

end


# The top-level PG namespace.
module PG

	# Library version
	VERSION = '0.20.0'

	# VCS revision
	REVISION = %q$Revision: 838985377b48 $

	class NotAllCopyDataRetrieved < PG::Error
	end

	### Get the PG library version. If +include_buildnum+ is +true+, include the build ID.
	def self::version_string( include_buildnum=false )
		vstring = "%s %s" % [ self.name, VERSION ]
		vstring << " (build %s)" % [ REVISION[/: ([[:xdigit:]]+)/, 1] || '0' ] if include_buildnum
		return vstring
	end


	### Convenience alias for PG::Connection.new.
	def self::connect( *args )
		return PG::Connection.new( *args )
	end


	require 'pg/exceptions'
	require 'pg/constants'
	require 'pg/coder'
	require 'pg/text_encoder'
	require 'pg/text_decoder'
	require 'pg/basic_type_mapping'
	require 'pg/type_map_by_column'
	require 'pg/connection'
	require 'pg/result'

end # module PG


# Backward-compatible aliase
PGError = PG::Error
