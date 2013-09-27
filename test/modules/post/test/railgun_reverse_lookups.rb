
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/railgun'

$:.push "test/lib" unless $:.include? "test/lib"
require 'module_test'

class Metasploit3 < Msf::Post

	include Msf::ModuleTest::PostTest
	include Msf::Post::Windows::Railgun

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'railgun_testing',
				'Description'   => %q{ This module will test railgun code used in post modules},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Platform'      => [ 'windows' ]
			))

		register_options(
			[
				OptInt.new("ERR_CODE",   [ false, "Error code to reverse lookup" ]),
				OptInt.new("WIN_CONST",  [ false, "Windows constant to reverse lookup" ]),
				OptRegexp.new("WCREGEX", [ false, "Regexp to apply to constant rev lookup" ]),
				OptRegexp.new("ECREGEX", [ false, "Regexp to apply to error code lookup" ]),
			], self.class)

	end

	def test_static

		it "should return a constant name given a const and a filter" do
			ret = true
			results = select_const_names(4, /^SERVICE/)

			ret &&= !!(results.kind_of? Array)
			# All of the returned values should match the filter and have the same value
			results.each { |const|
				ret &&= !!(const =~ /^SERVICE/)
				ret &&= !!(session.railgun.constant_manager.parse(const) == 4)
			}

			# Should include things that match the filter and the value
			ret &&= !!(results.include? "SERVICE_RUNNING")
			# Should NOT include things that match the value but not the filter
			ret &&= !!(not results.include? "CLONE_FLAG_ENTITY")

			ret
		end

		it "should return an error string given an error code" do
			ret = true
			results = lookup_error(0x420, /^ERROR_SERVICE/)
			ret &&= !!(results.kind_of? Array)
			ret &&= !!(results.length == 1)

			ret
		end

	end

	def test_datastore

		if (datastore["WIN_CONST"])
			it "should look up arbitrary constants" do
				ret = true
				results = select_const_names(datastore['WIN_CONST'], datastore['WCREGEX'])
				#vprint_status("RESULTS:  #{results.class} #{results.pretty_inspect}")

				ret
			end
		end

		if (datastore["ERR_CODE"])
			it "should look up arbitrary error codes" do
				ret = true
				results = lookup_error(datastore['ERR_CODE'], datastore['ECREGEX'])
				#vprint_status("RESULTS:  #{results.class} #{results.inspect}")

				ret
			end
		end

	end
end


