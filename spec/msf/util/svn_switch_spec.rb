require 'spec_helper'

require 'msf/util/switch'

describe Msf::Util::SvnSwitch do
	it 'should exist' do
		subject.should be_a ::Msf::Util::SvnSwitch
	end

	describe '.exec' do

		it 'should fail when passed a string' do
			expect {
				subject.exec("some string")
			}.to raise_error
		end

		it 'should fail when passed a non-cmd' do
			expect {
				subject.exec(:foobar)
			}.to raise_error
		end

		it 'should return true or false when it gets a valid command' do
			[TrueClass, FalseClass].should include subject.exec(:info_cmd).class
		end

	end
end

