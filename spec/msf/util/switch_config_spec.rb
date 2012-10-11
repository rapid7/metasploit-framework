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

describe Msf::Util::SwitchConfig do

	describe '.msfbase' do
		it 'should return the base install directory for Metasploit' do
			pwd = File.expand_path(File.dirname(__FILE__))
			top = File.expand_path(File.join(pwd, "..", "..", ".."))
			subject.msfbase.should == top
		end
	end

	describe '.i' do
		it 'should be an integer' do
			subject.i.should be_a_kind_of Integer
		end

		it 'should be random if undefined' do
			obj1 = Msf::Util::SwitchConfig.new
			obj2 = Msf::Util::SwitchConfig.new
			obj1.i.should_not == obj2.i
		end

		it 'should be fixed if defined' do
			i = 4321
			new_obj = Msf::Util::SwitchConfig.new(i)
			new_obj.i == i
		end

	end

	describe '.github_svn_checkout_target' do
		it 'should return the target subdir for the github svn checkout' do
			subject.github_svn_checkout_target.should_not be_empty
			subject.github_svn_checkout_target.should include subject.msfbase
		end
	end

	describe '.new_svn_checkout' do
		it 'should be the same as github_svn_checkout_target' do
			subject.new_svn_checkout.should == subject.github_svn_checkout_target
		end
	end

	describe '.new_source' do
		it 'should return an svn source for Metasploit checkouts' do
			subject.new_source.should == 'https://github.com/rapid7/metasploit-framework/trunk'
		end
	end

	describe '.svn_binary' do
		it 'should return the absolute path to the svn bin' do
			subject.svn_binary.should match /svn$/
		end
	end

	describe '.svn_version' do
		it 'should return the version of SVN' do
			subject.svn_version.should match /^1\.[67]/
		end
	end

	describe '.checkout_cmd' do
		it 'should construct a valid SVN checkout command' do
			subject.checkout_cmd.should match /svn /
		end

	end

end
