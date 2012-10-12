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
		it 'should return true or false when it gets a valid command' do
			[TrueClass, FalseClass].should include subject.system(:info_cmd).class
		end
	end

	describe '.delete_new_svn_checkout' do
		it 'should attempt to rm -rf the named directory' do
			subject.delete_new_svn_checkout.should == [subject.config.new_svn_checkout]
		end
	end

	describe '.create_untracked_files_list' do

		before(:all) do
			FileUtils.mkdir subject.config.new_svn_checkout
		end
		after(:all) do
			FileUtils.rm_rf subject.config.new_svn_checkout
		end

		it 'should create a file in the temp checkout' do
			subject.create_untracked_files_list.should =~ /#{subject.config.new_svn_checkout}/
			subject.create_untracked_files_list.should =~ /msf-svn-untracked\.txt$/
			File.readable?(subject.config.untracked_files_list).should be true
		end

		it 'should write a list of untracked files to that file' do
			fname = subject.config.untracked_files_list
			fdata = File.open(fname, "rb") {|f| f.read f.stat.size}
			fdata.should_not be_nil
		end

		context 'given some untracked files' do
			it 'should list those files' do
				pending('test in an SVN environment')
			end
		end

	end

end

