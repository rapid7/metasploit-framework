require 'spec_helper'

require 'msf/util/switch'

describe Msf::Util::SvnSwitch do

	before(:all) do
		@subject = Msf::Util::SvnSwitch.new(1234,"/tmp/msf3-anon")
	end
	subject {@subject}

	it 'should exist' do
		subject.should be_a ::Msf::Util::SvnSwitch
	end

	it 'should take a configurable i and msfbase' do
		i = 1234
		base = "/tmp/msf3-anon"
		obj = Msf::Util::SvnSwitch.new(i, base)
		obj.should be
	end

	describe '.config' do
		it 'should return a config object' do
			subject.config.should be_a Msf::Util::SvnSwitchConfig
		end
	end

	describe '.msfbase' do
		it 'should return a path' do
			File.directory?(subject.msfbase).should be_true
		end
	end

	describe '.system' do
		it 'should fail when passed a string' do
			expect {
				subject.system("some string")
			}.to raise_error
		end
		it 'should fail when passed a non-cmd' do
			expect {
				subject.system(:foobar)
			}.to raise_error
		end
		it 'should return false when the commands fails' do
			subject.system(:info_cmd).should be_false
		end
		it 'should return true when the command succeeds' do
			subject.system(:status_current_cmd).should be_true
		end
	end

	describe '.delete_new_svn_checkout' do
		it 'should attempt to rm -rf the new checkout' do
			checkout_dir = File.join(subject.msfbase, "msf-github-1234")
			FileUtils.mkdir(checkout_dir)
			subject.delete_new_svn_checkout.should == [checkout_dir]
			File.exist? checkout_dir
		end
	end

end

