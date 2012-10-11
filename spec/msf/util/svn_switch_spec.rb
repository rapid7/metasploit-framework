require 'spec_helper'

#
# Core
#

# Temporary files
require 'tempfile'
# add mktmpdir to Dir
require 'tmpdir'

#
# Project
#

require 'msf/util/switch'

describe Msf::Util::SvnSwitch do
	it 'should exist' do
		subject.should be_a ::Msf::Util::SvnSwitch
	end

	describe '.exec' do

		it 'should fail when it gets a string' do
			expect {
				subject.exec("some string")
			}.to raise_error
		end

		it 'should fail when it gets a non-cmd' do
			expect {
				subject.exec(:foobar)
			}.to raise_error
		end

		it 'should exec and return true or false when it gets a valid command' do
			[TrueClass, FalseClass].should include subject.exec(:cleanup_cmd).class
		end

	end
end

