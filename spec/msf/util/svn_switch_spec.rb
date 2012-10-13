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

	describe '.backup_local_files' do

		before(:each) do
			@new_svn_checkout = subject.config.new_svn_checkout
			FileUtils.mkdir @new_svn_checkout
			msfbase = subject.msfbase
			%x[touch #{@test_file_1 = File.join(msfbase,"test1.txt")}]
			@test_dir = FileUtils.mkdir File.join(msfbase,"testdir")
			%x[touch #{@test_file_2 = File.join(@test_dir,"test2.txt")}]
			@test_dir_deep = FileUtils.mkdir_p File.join(msfbase,"testdir_deep","another","another")
		end
		after(:each) do
			FileUtils.rm_rf @new_svn_checkout
			FileUtils.rm_rf @test_file_1
			FileUtils.rm_rf @test_dir
			FileUtils.rm_rf File.join(subject.config.msfbase, "testdir_deep")
		end

		it {should respond_to :backup_local_files}
		it 'should backup eligible untracked files' do
			subject.backup_local_files
			file_test = File.exist? File.join(@new_svn_checkout, "test1.txt")
			file_test.should be_true
		end
		it 'should backup nested files' do
			subject.backup_local_files
			subfile = File.join("testdir", "test2.txt")
			file_test = File.exist? File.join(@new_svn_checkout, subfile)
			file_test.should be_true
		end
		it 'should backup directories' do
			subject.backup_local_files
			file_test = File.directory? File.join(@new_svn_checkout, "testdir")
			file_test.should be_true
		end
		it 'should backup nested directories' do
			subject.backup_local_files
			subdir = File.join("testdir_deep", "another", "another")
			file_test = File.directory? File.join(@new_svn_checkout, subdir)
			file_test.should be_true
		end
		it 'should overwrite destination files' do
			overwrite_file = File.join(@new_svn_checkout, "testdir_deep")
			fh = File.open overwrite_file, "wb"
			fh.puts "I'm totally not a directory"
			fh.close
			subject.backup_local_files
			file_test = File.directory? overwrite_file
		end
	end

	describe '.copy_new_checkout' do
		it {should respond_to :copy_new_checkout}
		before(:each) do
			@new_svn_checkout = subject.new_svn_checkout
			@msfbase = subject.msfbase
			fname = File.join(@msfbase,"HACKING")
			@hacking_data = File.open(fname, "rb") {|f| f.read f.stat.size}
			FileUtils.mkdir @new_svn_checkout
			fh = File.open(File.join(@new_svn_checkout, "new_test.txt"), "wb")
			fh.close
			FileUtils.cp(fh.path, File.join(@new_svn_checkout, "HACKING"))
		end
		after(:each) do
			fname = File.join(@msfbase,"HACKING")
			FileUtils.rm_rf @new_svn_checkout
			FileUtils.rm_rf File.join(@msfbase, "new_test.txt")
			fh = File.open(fname, "wb")
			fh.write @hacking_data
			fh.close
		end

		it 'should copy new files from the new checkout to the current msfbase' do
			subject.copy_new_checkout
			fname = File.join(@msfbase, "new_test.txt")
			File.exist?(fname).should be_true
		end
		it 'should overwrite files in msfbase from the new checkout' do
			subject.copy_new_checkout
			fname = File.join(@msfbase, "HACKING")
			File.stat(fname).size.should be_zero
		end
	end

end

