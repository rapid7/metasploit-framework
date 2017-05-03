require 'spec_helper'

require 'msf/util/switch'

describe Msf::Util::SvnSwitchConfig do
	it 'should exist' do
		subject.should be_a ::Msf::Util::SvnSwitchConfig
	end

	before(:each) do
		# Yes, this is requiring a very specific path to an SVN checkout.
		# Someone with more rspec smarts than me can resolve this. That
		# someone might be me from the future.
		checkout_dir = "#{ENV['HOME']}/svn/msf3-anon"
		@subject = Msf::Util::SvnSwitchConfig.new(1234, checkout_dir)
		pwd = File.expand_path(File.dirname(__FILE__))
		@top = File.expand_path(File.join(pwd, "..", "..", ".."))
	end
	subject {@subject}

	describe '.msfbase' do
		context 'when msfbase has not been set' do
			it 'should return the base install directory for Metasploit' do
				fake_subject = subject.class.new
				fake_subject.msfbase.should == @top
			end
		end
		context 'when msfbase has been set' do
			it 'should return the specified directory' do
				my_msfbase = "#{ENV['HOME']}/svn/msf3-anon"
				subject.msfbase.should == my_msfbase
			end
			it 'should return the real msfbase when nil' do
				fake_subject = subject.class.new
				fake_subject.msfbase = nil
				fake_subject.msfbase.should == @top
			end
		end
	end

	describe '.i' do
		it 'should be an integer' do
			subject.i.should be_an Integer
		end
		context 'when undefined' do
			it 'should be random' do
			obj1 = Msf::Util::SvnSwitchConfig.new
			obj2 = Msf::Util::SvnSwitchConfig.new
			obj1.i.should_not == obj2.i
			end
		end
		context 'when defined' do
			it 'should be fixed' do
				i = 4321
				new_obj = Msf::Util::SvnSwitchConfig.new(i)
				new_obj.i == i
			end
		end
	end

	describe '.github_svn_checkout_target' do
		it 'should return the target subdir for the github svn checkout' do
			subject.github_svn_checkout_target.should_not be_empty
			subject.github_svn_checkout_target.should match /#{subject.msfbase}/
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

	describe '.cleanup_current_cmd' do
		it 'svn cleanup current should cleanup the current dir' do
			subject.cleanup_current_cmd.should be_a Array
			File.executable_real?(subject.cleanup_current_cmd.first).should be true
			subject.cleanup_current_cmd.join(' ').should match /svn cleanup #{subject.msfbase}/
		end
	end

	describe '.cleanup_cmd' do
		it 'svn cleanup should be a valid command' do
			subject.cleanup_cmd.should be_a Array
			File.executable_real?(subject.cleanup_cmd.first).should be true
			subject.cleanup_cmd.join(' ').should match /svn cleanup #{subject.new_svn_checkout}/
		end
	end

	describe '.stage_cmd' do
		it 'svn update --non-recursive be a valid command' do
			subject.stage_cmd.should be_a Array
			File.executable_real?(subject.stage_cmd.first).should be true
			subject.stage_cmd.join(' ').should match /svn update --non-recursive #{subject.new_svn_checkout}\/trunk/
		end
	end

	describe '.update_cmd' do
		it 'svn update should be a valid command' do
			subject.update_cmd.should be_a Array
			File.executable_real?(subject.update_cmd.first).should be true
			subject.update_cmd.join(' ').should match /svn update --set-depth infinity #{subject.new_svn_checkout}\/trunk/
		end
	end

	describe '.update_current_cmd' do
		it 'svn update current should be a valid command' do
			subject.update_current_cmd.should be_a Array
			File.executable_real?(subject.update_current_cmd.first).should be true
			subject.update_current_cmd.join(' ').should match /svn update #{subject.msfbase}/
		end
	end

	describe '.info_cmd' do
		it 'svn info should be a valid command' do
			subject.info_cmd.should be_a Array
			File.executable_real?(subject.info_cmd.first).should be true
			subject.info_cmd.join(' ').should match /svn info #{subject.new_svn_checkout}\/trunk/
		end
	end

	describe '.revert_gemfile_current_cmd' do
		it 'svn revert should be a valid command' do
			subject.revert_gemfile_current_cmd.should be_a Array
			File.executable_real?(subject.revert_gemfile_current_cmd.first).should be true
			subject.revert_gemfile_current_cmd.join(' ').should match /svn revert #{subject.msfbase}\/Gemfile.lock/
		end
	end

	describe '.status_current_cmd' do
		it 'svn status should be a valid command' do
			subject.status_current_cmd.should be_a Array
			File.executable_real?(subject.status_current_cmd.first).should be true
			subject.status_current_cmd.join(' ').should match /svn status #{subject.msfbase}/
		end
	end

	before(:each) do
		@test_fname = File.join(subject.msfbase, "HACKING")
		fh = File.open(@test_fname, "rb")
		@hacking_data = fh.read fh.stat.size
		fh.close
		fh = File.open(@test_fname, "wb")
		fh.print "And here's a change."
		fh.close
	end
	after(:each) do
		@test_fname = File.join(subject.msfbase, "HACKING")
		fh = File.open(@test_fname, "wb")
		fh.write @hacking_data
		fh.close
	end

	describe '.locally_modified_files' do
		it 'should return an array' do
			subject.locally_modified_files.should be_an Array
		end
		context 'given some untracked files' do
			it 'should have some elements' do
				subject.locally_modified_files.should include(@test_fname)
			end
		end
		context 'given no untracked files' do
			it 'should have no elements' do
				fake_subject = subject.class.new(666, '/tmp')
				fake_subject.locally_modified_files.size.should be_zero
			end
		end
	end

	describe '.switchable?' do
		context 'when there are no unexpectedly untracked files' do
			it 'should be switchable' do
				subject.should be_switchable
			end
		end
		context 'when there are missing files' do
			before(:each) do
				FileUtils.rm(@test_fname)
			end
			after(:each) do
				fh = File.open(@test_fname, "wb")
				fh.write @hacking_data
				fh.close
			end
			it 'should not be switchable' do
				subject.should_not be_switchable
			end
		end
		
	end

end

