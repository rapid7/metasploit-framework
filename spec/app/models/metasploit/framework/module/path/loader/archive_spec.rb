# -*- coding:binary -*-
require 'spec_helper'

describe Metasploit::Framework::Module::Path::Loader::Archive do
	subject(:loader) do
		described_class.new
	end

	let(:enabled_module_type) do
		Metasploit::Model::Module::Type::EXPLOIT
	end

	let(:enabled_module_type_directory) do
		Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[enabled_module_type]
	end

	let(:framework) do
		mock('Framework')
	end

	let(:module_extension) do
		'.rb'
	end

	let(:module_manager) do
		# DO NOT mock module_manager to ensure that no protected methods are being called.
		Msf::ModuleManager.new(framework, [enabled_module_type])
	end

	let(:reference_name) do
		FactoryGirl.generate :metasploit_model_module_ancestor_reference_name
	end

	subject do
		described_class.new(module_manager)
	end

	context '#each_module_ancestor' do
		include_context 'DatabaseCleaner'

		subject(:each_module_ancestor) do
			with_established_connection do
				loader.send(:each_module_ancestor, module_path, &block)
			end
		end

		let(:archive_pathname) do
			Metasploit::Model::Spec.temporary_pathname.join(
					"rspec#{Metasploit::Model::Module::Path::ARCHIVE_EXTENSION}"
			)
		end

		let(:disabled_module_content) do
			<<-EOS
				class Metasploit3 < Msf::Auxiliary
        end
			EOS
		end

		let(:disabled_module_type) do
		  Metasploit::Model::Module::Type::AUX
		end

		let(:disabled_module_type_directory) do
			Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[disabled_module_type]
		end

		let(:enabled_module_content) do
			<<-EOS
        class Metasploit3 < Msf::Exploit::Remote
        end
			EOS
		end

		let(:module_path) do
			with_established_connection {
				ActiveRecord::Base.connection_pool.with_connection {
					FactoryGirl.create(
							:mdm_module_path,
							:real_path => archive_pathname.to_path
					)
				}
			}
		end

		let(:options) do
			{}
		end

		before(:each) do
			modules_pathname = Metasploit::Model::Spec.temporary_pathname.join(
					'modules'
			)

			# make a type directory that should be ignored because it's not enabled
			disabled_module_type_pathname = modules_pathname.join(
					disabled_module_type_directory
			)
			disabled_module_type_pathname.mkpath

			#
			# create a valid module in the disabled type directory to make sure it's the enablement that's preventing the
			# yield
			#

			disabled_module_pathname = disabled_module_type_pathname.join("#{disabled_module_type}#{module_extension}")

			disabled_module_pathname.open('wb') do |f|
				f.write(disabled_module_content)
			end

			# make a type directory that should not be ignored because it is enabled
			enabled_module_pathname = modules_pathname.join(
					enabled_module_type_directory,
					"#{reference_name}#{module_extension}"
			)
			# use parent because reference_name will contain additional directories
			enabled_module_pathname.parent.mkpath

			enabled_module_pathname.open('wb') do |f|
				f.write(enabled_module_content)
			end

			modules_path = modules_pathname.to_path
			FastLib.dump(
					archive_pathname.to_path,
					FastLib::FLAG_COMPRESS.to_s(16),
					modules_path,
					modules_path
			)

			# @todo Fix https://www.pivotaltracker.com/story/show/38730815 and the cache won't need to be cleared as a work-around
			FastLib.cache.clear

			loader.stub(:module_type_enabled?).with(disabled_module_type).and_return(false)
			loader.stub(:module_type_enabled?).with(enabled_module_type).and_return(true)
		end

		it 'should use a persisted module path' do
			module_path.should be_persisted
		end

		# this checks that the around(:each) is working
		it 'should have an existent FastLib' do
			archive_pathname.should exist
		end

		it 'should ignore types that are not enabled' do
			with_established_connection do
				loader.send(:each_module_ancestor, module_path, options) do |module_ancestor|
					module_ancestor.module_type.should_not == disabled_module_type
				end
			end
		end

		it 'should yield (parent_path, type, module_reference_name) with parent_path equal to the archive path' do
			subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
				parent_path.should == @archive_path
			end
		end

		it 'should yield (parent_path, type, module_reference_name) with type equal to enabled type' do
			module_manager.module_type_enabled?(enabled_module_type).should be_true

			subject.send(:each_module_reference_name, @archive_path) do |parent_path, type, module_reference_name|
				type.should == enabled_module_type
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
		subject(:loadable?) do
			loader.loadable?(module_path)
		end

		let(:module_path) do
			double('Metasploit::Model::Module::Path', :archive? => archive)
		end

		context 'with archive' do
			let(:archive) do
				true
			end

			it { should be_true }
		end

		context 'without archive' do
			let(:archive) do
				false
			end

			it { should be_false }
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
			enabled_module_type
		end

		let(:type_directory) do
			enabled_module_type_directory
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
