# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'

describe Msf::Modules::Loader::Archive do
	let(:archive_extension) do
		'.fastlib'
	end

	context 'CONSTANTS' do
		it 'should have extension' do
			described_class::ARCHIVE_EXTENSION.should == archive_extension
		end
	end

	context 'instance methods' do
		let(:enabled_type) do
			'exploit'
		end

		let(:enabled_type_directory) do
			'exploits'
		end

		let(:framework) do
			mock('Framework')
		end

		let(:module_extension) do
			'.rb'
		end

		let(:module_manager) do
			# DO NOT mock module_manager to ensure that no protected methods are being called.
		  Msf::ModuleManager.new(framework, [enabled_type])
		end

		let(:module_reference_name) do
			'module/reference/name'
		end

		subject do
			described_class.new(module_manager)
		end

		context '#each_module_reference_name' do
			let(:disabled_module_content) do
				<<-EOS
				class Metasploit3 < Msf::Auxiliary
        end
				EOS
			end

			let(:disabled_type) do
				'auxiliary'
			end

			let(:disabled_type_directory) do
				'auxiliary'
			end

			let(:enabled_module_content) do
        <<-EOS
        class Metasploit3 < Msf::Exploit::Remote
        end
        EOS
			end

			around(:each) do |example|
				Dir.mktmpdir do |directory|
					@base_path = directory

					# make a .svn directory to be ignored
					subversion_path = File.join(@base_path, '.svn')
					FileUtils.mkdir_p subversion_path

					# make a type directory that should be ignored because it's not enabled
					disabled_type_path = File.join(@base_path, disabled_type_directory)
					FileUtils.mkdir_p disabled_type_path

					#
					# create a valid module in the disabled type directory to make sure it's the enablement that's preventing the
					# yield
					#

					disabled_module_path = File.join(disabled_type_path, "#{disabled_type}#{module_extension}")

					File.open(disabled_module_path, 'wb') do |f|
						f.write(disabled_module_content)
					end

					# make a type directory that should not be ignored because it is enabled
					enabled_module_path = File.join(
							@base_path,
							enabled_type_directory,
							"#{module_reference_name}#{module_extension}"
					)
					enabled_module_directory = File.dirname(enabled_module_path)
					FileUtils.mkdir_p enabled_module_directory

					File.open(enabled_module_path, 'wb') do |f|
						f.write(enabled_module_content)
					end

					Dir.mktmpdir do |archive_directory|
						@archive_path = File.join(archive_directory, "rspec#{archive_extension}")
						FastLib.dump(@archive_path, FastLib::FLAG_COMPRESS.to_s(16), @base_path, @base_path)

						# @todo Fix https://www.pivotaltracker.com/story/show/38730815 and the cache won't need to be cleared as a work-around
						FastLib.cache.clear

						example.run
					end
				end
			end

			# this checks that the around(:each) is working
			it 'should have an existent FastLib' do
				File.exist?(@archive_path).should be_true
			end

			it 'should ignore .svn directories' do
				subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
					parent_path.should_not include('.svn')
				end
			end

			it 'should ignore types that are not enabled' do
				module_manager.type_enabled?(disabled_type).should be_false

				subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
					type.should_not == disabled_type
				end
			end

			it 'should yield (parent_path, type, module_reference_name) with parent_path equal to the archive path' do
				subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
					parent_path.should == @archive_path
				end
			end

			it 'should yield (parent_path, type, module_reference_name) with type equal to enabled type' do
				module_manager.type_enabled?(enabled_type).should be_true

				subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
					type.should == enabled_type
				end
			end

			it 'should yield (path, type, module_reference_name) with module_reference_name without extension' do
				subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
					module_reference_name.should_not match(/#{Regexp.escape(module_extension)}$/)
					module_reference_name.should == module_reference_name
				end
			end

			# ensure that the block is actually being run so that shoulds in the block aren't just being skipped
			it 'should yield the correct number of tuples' do
				actual_count = 0

				subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
					actual_count += 1
				end

				actual_count.should == 1
			end
		end

		context '#loadable?' do
			it 'should return true if the path has ARCHIVE_EXTENSION as file extension' do
				path = "path/to/archive#{archive_extension}"

				File.extname(path).should == described_class::ARCHIVE_EXTENSION
				subject.loadable?(path).should be_true
			end

			it 'should return false if the path contains ARCHIVE_EXTENSION, but it is not the file extension' do
				path = "path/to/archive#{archive_extension}.bak"

				path.should include(described_class::ARCHIVE_EXTENSION)
				File.extname(path).should_not == described_class::ARCHIVE_EXTENSION
				subject.loadable?(path).should be_false
			end
		end

		context '#module_path' do
			let(:parent_path) do
				"path/to/archive#{archive_extension}"
			end

			let(:type) do
				'exploit'
			end

			let(:type_directory) do
				'exploits'
			end

			it 'should use typed_path to convert the type name to a type directory' do
				subject.should_receive(:typed_path).with(type, module_reference_name)

				subject.send(:module_path, parent_path, type, module_reference_name)
			end

			it "should separate the archive path from the entry path with '::'" do
				module_path = subject.send(:module_path, parent_path, type, module_reference_name)

				module_path.should == "#{parent_path}::#{type_directory}/#{module_reference_name}.rb"
			end
		end

		context '#read_module_path' do
			let(:module_reference_name) do
				'windows/smb/ms08_067_netapi'
			end

			let(:type) do
			  enabled_type
			end

			let(:type_directory) do
			  enabled_type_directory
			end

			let(:archived_path) do
				File.join(type_directory, "#{module_reference_name}#{module_extension}")
			end

			let(:base_path) do
				File.join(Msf::Config.install_root, 'modules')
			end

			let(:flag_string) do
				flags.to_s(16)
			end

			let(:flags) do
				0x0
			end

			let(:unarchived_path) do
				File.join(base_path, archived_path)
			end

			it 'should read modules that exist' do
				File.exist?(unarchived_path).should be_true
			end

			around(:each) do |example|
				Dir.mktmpdir do |directory|
					@parent_path = File.join(directory, 'rspec.fastlib')

					FastLib.dump(@parent_path, flag_string, base_path, unarchived_path)

					# @todo Fix https://www.pivotaltracker.com/story/show/38730815 so cache from dump is correct
					FastLib.cache.clear

					example.run
				end
			end

			context 'with uncompressed archive' do
				it_should_behave_like 'Msf::Modules::Loader::Archive#read_module_content'
			end

			context 'with compressed archive' do
				let(:flags) do
					FastLib::FLAG_COMPRESS
				end

				it_should_behave_like 'Msf::Modules::Loader::Archive#read_module_content'
			end
		end
	end
end
