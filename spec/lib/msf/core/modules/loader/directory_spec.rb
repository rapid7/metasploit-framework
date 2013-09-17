# -*- coding:binary -*-
require 'spec_helper'
require 'msf/core'
require 'msf/core/modules/loader/directory'

require 'msf/core'

describe Msf::Modules::Loader::Directory do
	context 'instance methods' do
		include_context 'Msf::Modules::Loader::Base'

		let(:module_manager) do
			double('Module Manager')
		end

		let(:module_path) do
			"#{parent_path}/exploits/#{module_reference_name}.rb"
		end

		let(:type) do
			'exploit'
		end

		subject do
			described_class.new(module_manager)
		end

		context '#load_module' do
			context 'with existent module_path' do
				let(:framework) do
					framework = double('Msf::Framework', :datastore => {})

					events = double('Events')
					events.stub(:on_module_load)
					events.stub(:on_module_created)
					framework.stub(:events => events)

					framework
				end

				let(:module_full_name) do
					"#{type}/#{module_reference_name}"
				end

				let(:module_manager) do
					Msf::ModuleManager.new(framework)
				end

				let(:module_reference_name) do
					'windows/smb/ms08_067_netapi'
				end

				it 'should load a module that can be created' do
					subject.load_module(parent_path, type, module_reference_name).should be_true

					created_module = module_manager.create(module_full_name)

					created_module.name.should == 'Microsoft Server Service Relative Path Stack Corruption'
				end

				context 'with module previously loaded' do
					before(:each) do
						subject.load_module(parent_path, type, module_reference_name)
					end

					# Payloads are defined as ruby Modules so they can behave differently
					context 'with payload' do
						let(:reference_name) do
							'stages/windows/x64/vncinject'
						end

						let(:type) do
							'payload'
						end

						it 'should not load the module' do
							subject.load_module(parent_path, type, module_reference_name).should be_false
						end
					end

					# Non-payloads are defined as ruby Classes
					context 'without payload' do
						let(:reference_name) do
							'windows/smb/ms08_067_netapi'
						end

						let(:type) do
							'exploit'
						end

						it 'should not load the module' do
							subject.load_module(parent_path, type, module_reference_name).should be_false
						end
					end
				end
			end

			context 'without existent module_path' do
				let(:module_reference_name) do
					'osx/armle/safari_libtiff'
				end

				let(:error) do
					Errno::ENOENT.new(module_path)
				end

				before(:each) do
					module_manager.stub(:file_changed? => true)
					module_manager.stub(:module_load_error_by_path => {})
				end

				it 'should not raise an error' do
					File.exist?(module_path).should be_false

					expect {
						subject.load_module(parent_path, type, module_reference_name)
					}.to_not raise_error
				end

				it 'should return false' do
					File.exist?(module_path).should be_false

					subject.load_module(parent_path, type, module_reference_name).should be_false
				end
			end
		end

		context '#read_module_content' do
			context 'with non-existent module_path' do
				let(:module_reference_name) do
					'osx/armle/safari_libtiff'
				end

				before(:each) do
					subject.stub(:load_error).with(module_path, kind_of(Errno::ENOENT))
				end

				# this ensures that the File.exist?(module_path) checks are checking the same path as the code under test
				it 'should attempt to open the expected module_path' do
					File.should_receive(:open).with(module_path, 'rb')
					File.exist?(module_path).should be_false

					subject.send(:read_module_content, parent_path, type, module_reference_name)
				end

				it 'should not raise an error' do
					expect {
						subject.send(:read_module_content, parent_path, type, module_reference_name)
					}.to_not raise_error
				end

				it 'should return an empty string' do
					subject.send(:read_module_content, parent_path, type, module_reference_name).should == ''
				end

				it 'should record the load error' do
					subject.should_receive(:load_error).with(module_path, kind_of(Errno::ENOENT))

					subject.send(:read_module_content, parent_path, type, module_reference_name).should == ''
				end
			end
		end
	end
end
