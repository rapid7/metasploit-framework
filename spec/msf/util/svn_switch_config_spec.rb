require 'spec_helper'

require 'msf/util/switch'

describe Msf::Util::SvnSwitchConfig do
	it 'should exist' do
		subject.should be_a ::Msf::Util::SvnSwitchConfig
	end

	describe '.msfbase' do
		it 'should return the base install directory for Metasploit' do
			pwd = File.expand_path(File.dirname(__FILE__))
			top = File.expand_path(File.join(pwd, "..", "..", ".."))
			subject.msfbase.should == top
		end
	end

	describe '.i' do
		it 'should be an integer' do
			subject.i.should be_a Integer
		end

		it 'should be random if undefined' do
			obj1 = Msf::Util::SvnSwitchConfig.new
			obj2 = Msf::Util::SvnSwitchConfig.new
			obj1.i.should_not == obj2.i
		end

		it 'should be fixed if defined' do
			i = 4321
			new_obj = Msf::Util::SvnSwitchConfig.new(i)
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
			subject.new_source.should == 'https://github.com/rapid7/metasploit-framework'
		end
	end

	describe '.svn_binary' do
		it 'should return the absolute path to the svn bin' do
			subject.svn_binary.should match /svn$/
			File.executable_real?(subject.svn_binary).should be true
		end
	end

	describe '.svn_version' do
		it 'should return the version of SVN' do
			subject.svn_version.should match /^1\.[67]/
		end
	end

	describe '.checkout_cmd' do
		it 'svn checkout should be a valid command' do
			subject.checkout_cmd.should be_a Array
			File.executable_real?(subject.checkout_cmd.first).should be true
			subject.checkout_cmd.join(' ').should match /svn checkout --non-recursive http/
		end
	end

	describe '.cleanup_cmd' do
		it 'svn cleanup should be a valid command' do
			subject.cleanup_cmd.should be_a Array
			File.executable_real?(subject.cleanup_cmd.first).should be true
			subject.cleanup_cmd.join(' ').should match /svn cleanup #{subject.msfbase}/
		end
	end

	describe '.update_cmd' do
		it 'svn update should be a valid command' do
			subject.update_cmd.should be_a Array
			File.executable_real?(subject.update_cmd.first).should be true
			subject.update_cmd.join(' ').should match /svn update #{subject.new_svn_checkout}\/trunk/
		end
	end

	describe '.info_cmd' do
		it 'svn info should be a valid command' do
			subject.info_cmd.should be_a Array
			File.executable_real?(subject.info_cmd.first).should be true
			subject.info_cmd.join(' ').should match /svn info #{subject.new_svn_checkout}\/trunk/
		end
	end

end

