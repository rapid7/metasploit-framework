require 'spec_helper'

require 'msf/util/switch'

describe Msf::Util::SvnSwitch do
	it 'should exist' do
		subject.should be_a ::Msf::Util::SvnSwitch
	end

	describe '.config' do
		it 'should return a config object' do
			subject.config.should be_a Msf::Util::SvnSwitchConfig
		end
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

