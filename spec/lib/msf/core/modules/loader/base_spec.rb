# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'

describe Msf::Modules::Loader::Base do
	include_context 'Msf::Modules::Loader::Base'

	let(:described_class_pathname) do
		root_pathname.join('lib', 'msf', 'core', 'modules', 'loader', 'base.rb')
	end

	let(:malformed_module_content) do
		<<-EOS
      class Metasploit3
        # purposeful typo to check that module path is used in backtrace
        inclde Exploit::Remote::Tcp
      end
		EOS
	end

	let(:module_content) do
		<<-EOS
			class Metasploit3 < Msf::Auxiliary
        # fully-qualified name is Msf::GoodRanking, so this will failing if lexical scope is not captured
        Rank = GoodRanking
        end
		EOS
	end

	let(:module_full_name) do
		"#{type}/#{module_reference_name}"
	end

	let(:module_path) do
		parent_pathname.join('auxiliary', 'rspec', 'mock.rb').to_s
	end

	let(:module_reference_name) do
		'rspec/mock'
	end

	let(:type) do
		Msf::MODULE_AUX
	end

	context 'CONSTANTS' do

		context 'DIRECTORY_BY_TYPE' do
			let(:directory_by_type) do
				described_class::DIRECTORY_BY_TYPE
			end

			it 'should be defined' do
				described_class.const_defined?(:DIRECTORY_BY_TYPE).should be_true
			end

			it 'should map Msf::MODULE_AUX to auxiliary' do
				directory_by_type[Msf::MODULE_AUX].should == 'auxiliary'
			end

			it 'should map Msf::MODULE_ENCODER to encoders' do
				directory_by_type[Msf::MODULE_ENCODER].should == 'encoders'
			end

			it 'should map Msf::MODULE_EXPLOIT to exploits' do
				directory_by_type[Msf::MODULE_EXPLOIT].should == 'exploits'
			end

			it 'should map Msf::MODULE_NOP to nops' do
				directory_by_type[Msf::MODULE_NOP].should == 'nops'
			end

			it 'should map Msf::MODULE_PAYLOAD to payloads' do
				directory_by_type[Msf::MODULE_PAYLOAD].should == 'payloads'
			end

			it 'should map Msf::MODULE_POST to post' do
				directory_by_type[Msf::MODULE_POST].should == 'post'
			end
		end

		context 'NAMESPACE_MODULE_LINE' do
			it 'should be line number for first line of NAMESPACE_MODULE_CONTENT' do
				file_lines = []

				described_class_pathname.open do |f|
					file_lines = f.to_a
				end

				# -1 because file lines are 1-based, but array is 0-based
				file_line = file_lines[described_class::NAMESPACE_MODULE_LINE - 1]

				constant_lines = described_class::NAMESPACE_MODULE_CONTENT.lines.to_a
				constant_line = constant_lines.first

				file_line.should == constant_line
			end
		end

		context 'NAMESPACE_MODULE_CONTENT' do
			context 'derived module' do
				let(:namespace_module_names) do
					['Msf', 'Modules', 'Mod617578696c696172792f72737065632f6d6f636b']
				end

				let(:namespace_module) do
					Object.module_eval(
							<<-EOS
							module #{namespace_module_names[0]}
                module #{namespace_module_names[1]}
                  module #{namespace_module_names[2]}
										#{described_class::NAMESPACE_MODULE_CONTENT}
                  end
                end
              end
					EOS
					)

					namespace_module_names.join('::').constantize
				end

				context 'loader' do
					it 'should be a read/write attribute' do
						loader = double('Loader')
						namespace_module.loader = loader

						namespace_module.loader.should == loader
					end
				end

				context 'module_eval_with_lexical_scope' do
					it 'should capture the lexical scope' do
						expect {
							namespace_module.module_eval_with_lexical_scope(module_content, module_path)
						}.to_not raise_error
					end

					context 'with malformed module content' do
						it 'should use module path in module_eval' do
							error = nil

							begin
								namespace_module.module_eval_with_lexical_scope(malformed_module_content, module_path)
							rescue NoMethodError => error
								# don't put the should in the rescue because if there is no error, then the example will still be
								# successful.
							end

							error.should_not be_nil
							error.backtrace[0].should include(module_path)
						end
					end
				end

				context 'parent_path' do
					it 'should be a read/write attribute' do
						parent_path = double('Parent Path')
						namespace_module.parent_path = parent_path

						namespace_module.parent_path.should == parent_path
					end
				end
			end
		end

		context 'MODULE_EXTENSION' do
			it 'should only support ruby source modules' do
				described_class::MODULE_EXTENSION.should == '.rb'
			end
		end

		context 'MODULE_SEPARATOR' do
			it 'should make valid module names' do
				name = ['Msf', 'Modules'].join(described_class::MODULE_SEPARATOR)
				name.constantize.should == Msf::Modules
			end
		end

		context 'NAMESPACE_MODULE_NAMES' do
			it 'should be under Msf so that Msf constants resolve from lexical scope' do
				described_class::NAMESPACE_MODULE_NAMES.should include('Msf')
			end

			it "should not be directly under Msf so that modules don't collide with core namespaces" do
				direct_index = described_class::NAMESPACE_MODULE_NAMES.index('Msf')
				last_index = described_class::NAMESPACE_MODULE_NAMES.length - 1

				last_index.should > direct_index
			end
		end

		context 'UNIT_TEST_REGEX' do
			it 'should match test suite files' do
				described_class::UNIT_TEST_REGEX.should match('rb.ts.rb')
			end

			it 'should match unit test files' do
				described_class::UNIT_TEST_REGEX.should match('rb.ut.rb')
			end
		end
	end

	context 'class methods' do
		context 'typed_path' do
			it 'should have MODULE_EXTENSION for the extension name' do
				typed_path = described_class.typed_path(Msf::MODULE_AUX, module_reference_name)

				File.extname(typed_path).should == described_class::MODULE_EXTENSION
			end

			# Don't iterate over a Hash here as that would too closely mirror the actual implementation and not test anything
			it_should_behave_like 'typed_path', 'Msf::MODULE_AUX' => 'auxiliary'
			it_should_behave_like 'typed_path', 'Msf::MODULE_ENCODER' => 'encoders'
			it_should_behave_like 'typed_path', 'Msf::MODULE_EXPLOIT' => 'exploits'
			it_should_behave_like 'typed_path', 'Msf::MODULE_NOP' => 'nops'
			it_should_behave_like 'typed_path', 'Msf::MODULE_PAYLOAD' => 'payloads'
			it_should_behave_like 'typed_path', 'Msf::MODULE_POST' => 'post'
		end
	end

	context 'instance methods' do
		let(:module_manager) do
			double('Module Manager', :module_load_error_by_path => {})
		end

		subject do
			described_class.new(module_manager)
		end

		context '#initialize' do
			it 'should set @module_manager' do
				loader = described_class.new(module_manager)
				loader.instance_variable_get(:@module_manager).should == module_manager
			end
		end

		context '#loadable?' do
			it 'should be abstract' do
				expect {
					subject.loadable?(parent_pathname.to_s)
				}.to raise_error(NotImplementedError)
			end
		end

		context '#load_module' do
			let(:parent_path) do
				parent_pathname.to_s
			end

			let(:type) do
				Msf::MODULE_AUX
			end

			before(:each) do
				subject.stub(:module_path => module_path)
			end

			it 'should call file_changed? with the module_path' do
				module_manager.should_receive(:file_changed?).with(module_path).and_return(false)

				subject.load_module(parent_path, type, module_reference_name, :force => false)
			end

			context 'without file changed' do
				before(:each) do
					module_manager.stub(:file_changed? => false)
				end

				it 'should return false if :force is false' do
					subject.load_module(parent_path, type, module_reference_name, :force => false).should be_false
				end

				it 'should not call #read_module_content' do
					subject.should_not_receive(:read_module_content)
					subject.load_module(parent_path, type, module_reference_name)
				end
      end

			context 'with file changed' do
				let(:module_full_name) do
					File.join('auxiliary', module_reference_name)
				end

				let(:namespace_module) do
					Msf::Modules.const_get(relative_name)
				end

				let(:relative_name) do
					'Mod617578696c696172792f72737065632f6d6f636b'
				end

				before(:each) do
					# capture in a local so that instance_eval can access it
					relative_name = self.relative_name

					# remove module from previous examples so reload error aren't logged
					if Msf::Modules.const_defined? relative_name
						Msf::Modules.instance_eval do
							remove_const relative_name
						end
					end

					# create an namespace module that can be restored
					module Msf
						module Modules
							module Mod617578696c696172792f72737065632f6d6f636b
								class Metasploit3 < Msf::Auxiliary

								end
							end
						end
					end

					@original_namespace_module = Msf::Modules::Mod617578696c696172792f72737065632f6d6f636b

					module_manager.stub(:delete).with(module_reference_name)
					module_manager.stub(:file_changed?).with(module_path).and_return(true)

					module_set = double('Module Set')
					module_set.stub(:delete).with(module_reference_name)
					module_manager.stub(:module_set).with(type).and_return(module_set)
				end

				it 'should call #namespace_module_transaction with the module full name and :reload => true' do
					subject.stub(:read_module_content => module_content)

					subject.should_receive(:namespace_module_transaction).with(module_full_name, hash_including(:reload => true))

					subject.load_module(parent_path, type, module_reference_name)
				end

				it 'should set the parent_path on the namespace_module to match the parent_path passed to #load_module' do
					module_manager.stub(:on_module_load)

					subject.stub(:read_module_content => module_content)

					subject.load_module(parent_path, type, module_reference_name).should be_true
					namespace_module.parent_path.should == parent_path
				end

				it 'should call #read_module_content to get the module content so that #read_module_content can be overridden to change loading behavior' do
					module_manager.stub(:on_module_load)

					subject.should_receive(:read_module_content).with(parent_path, type, module_reference_name).and_return(module_content)
					subject.load_module(parent_path, type, module_reference_name).should be_true
				end

				it 'should call namespace_module.module_eval_with_lexical_scope with the module_path' do
					subject.stub(:read_module_content => malformed_module_content)
					module_manager.stub(:on_module_load)

					# if the module eval error includes the module_path then the module_path was passed along correctly
					subject.should_receive(:elog).with(/#{Regexp.escape(module_path)}/)
					subject.load_module(parent_path, type, module_reference_name, :reload => true).should be_false
				end

				context 'with empty module content' do
					before(:each) do
						subject.stub(:read_module_content).with(parent_path, type, module_reference_name).and_return('')
					end

					it 'should return false' do
						subject.load_module(parent_path, type, module_reference_name).should be_false
					end

					it 'should not attempt to make a new namespace_module' do
						subject.should_not_receive(:namespace_module_transaction)
						subject.load_module(parent_path, type, module_reference_name).should be_false
					end
				end

				context 'with errors from namespace_module_eval_with_lexical_scope' do
					before(:each) do
						@namespace_module = double('Namespace Module')
						@namespace_module.stub(:parent_path=)

						subject.stub(:namespace_module_transaction).and_yield(@namespace_module)
						module_content = double('Module Content', :empty? => false)
						subject.stub(:read_module_content).and_return(module_content)
					end

					context 'with Interrupt' do
						it 'should re-raise' do
							@namespace_module.stub(:module_eval_with_lexical_scope).and_raise(Interrupt)

							expect {
								subject.load_module(parent_path, type, module_reference_name)
							}.to raise_error(Interrupt)
						end
					end

					context 'with other Exception' do
						let(:backtrace) do
							[
								'Backtrace Line 1',
								'Backtrace Line 2'
							]
						end

						let(:error) do
							error_class.new(error_message)
						end

						let(:error_class) do
							ArgumentError
						end

						let(:error_message) do
							'This is rspec.  Your argument is invalid.'
						end

						before(:each) do
							@namespace_module.stub(:module_eval_with_lexical_scope).and_raise(error)

							@module_load_error_by_path = {}
							module_manager.stub(:module_load_error_by_path => @module_load_error_by_path)

							error.stub(:backtrace => backtrace)
						end

						context 'with version compatibility' do
							before(:each) do
								@namespace_module.stub(:version_compatible!).with(module_path, module_reference_name)
							end

							it 'should record the load error using the original error' do
								subject.should_receive(:load_error).with(module_path, error)
								subject.load_module(parent_path, type, module_reference_name).should be_false
							end
						end

						context 'without version compatibility' do
							let(:version_compatibility_error) do
								Msf::Modules::VersionCompatibilityError.new(
										:module_path => module_path,
										:module_reference_name => module_reference_name,
										:minimum_api_version => infinity,
										:minimum_core_version => infinity
								)
							end

							let(:infinity) do
								0.0 / 0.0
							end

							before(:each) do
								@namespace_module.stub(
										:version_compatible!
								).with(
										module_path,
										module_reference_name
								).and_raise(
										version_compatibility_error
								)
							end

							it 'should record the load error using the Msf::Modules::VersionCompatibilityError' do
								subject.should_receive(:load_error).with(module_path, version_compatibility_error)
								subject.load_module(parent_path, type, module_reference_name).should be_false
							end
						end

						it 'should return false' do
							@namespace_module.stub(:version_compatible!).with(module_path, module_reference_name)

							subject.load_module(parent_path, type, module_reference_name).should be_false
						end
					end
				end

				context 'without module_eval errors' do
					before(:each) do
						@namespace_module = double('Namespace Module')
						@namespace_module.stub(:parent_path=)
						@namespace_module.stub(:module_eval_with_lexical_scope).with(module_content, module_path)

						metasploit_class = double('Metasploit Class', :parent => @namespace_module)
						@namespace_module.stub(:metasploit_class! => metasploit_class)

						subject.stub(:namespace_module_transaction).and_yield(@namespace_module)

						subject.stub(:read_module_content).with(parent_path, type, module_reference_name).and_return(module_content)

						@module_load_error_by_path = {}
						module_manager.stub(:module_load_error_by_path => @module_load_error_by_path)
					end

					it 'should check for version compatibility' do
						module_manager.stub(:on_module_load)

						@namespace_module.should_receive(:version_compatible!).with(module_path, module_reference_name)
						subject.load_module(parent_path, type, module_reference_name)
					end

					context 'without version compatibility' do
						let(:version_compatibility_error) do
							Msf::Modules::VersionCompatibilityError.new(
									:module_path => module_path,
									:module_reference_name => module_reference_name,
									:minimum_api_version => infinity,
									:minimum_core_version => infinity
							)
						end

						let(:infinity) do
							0.0 / 0.0
						end

						before(:each) do
							@namespace_module.stub(
									:version_compatible!
							).with(
									module_path,
									module_reference_name
							).and_raise(
									version_compatibility_error
							)
						end

						it 'should record the load error' do
							subject.should_receive(:load_error).with(module_path, version_compatibility_error)
							subject.load_module(parent_path, type, module_reference_name).should be_false
						end

						it 'should return false' do
							subject.load_module(parent_path, type, module_reference_name).should be_false
						end

						it 'should restore the old namespace module' do

						end
					end

					context 'with version compatibility' do
						before(:each) do
							@namespace_module.stub(:version_compatible!).with(module_path, module_reference_name)

							module_manager.stub(:on_module_load)
						end

						context 'without metasploit_class' do
							let(:error) do
								Msf::Modules::MetasploitClassCompatibilityError.new(
										:module_path => module_path,
										:module_reference_name => module_reference_name
								)
							end

							before(:each) do
								@namespace_module.stub(:metasploit_class!).with(module_path, module_reference_name).and_raise(error)
							end

							it 'should record load error' do
								subject.should_receive(
										:load_error
								).with(
										module_path,
										kind_of(Msf::Modules::MetasploitClassCompatibilityError)
								)
								subject.load_module(parent_path, type, module_reference_name).should be_false
							end

							it 'should return false' do
								subject.load_module(parent_path, type, module_reference_name).should be_false
							end

							it 'should restore the old namespace module' do
								subject.load_module(parent_path, type, module_reference_name).should be_false
								Msf::Modules.const_defined?(relative_name).should be_true
								Msf::Modules.const_get(relative_name).should == @original_namespace_module
							end
						end

						context 'with metasploit_class' do
							let(:metasploit_class) do
								double('Metasploit Class')
							end

							before(:each) do
								@namespace_module.stub(:metasploit_class! => metasploit_class)
							end

							it 'should check if it is usable' do
								subject.should_receive(:usable?).with(metasploit_class).and_return(true)
								subject.load_module(parent_path, type, module_reference_name).should be_true
							end

							context 'without usable metasploit_class' do
								before(:each) do
									subject.stub(:usable? => false)
								end

								it 'should log information' do
									subject.should_receive(:ilog).with(/#{module_reference_name}/, 'core', LEV_1)
									subject.load_module(parent_path, type, module_reference_name).should be_false
								end

								it 'should return false' do
									subject.load_module(parent_path, type, module_reference_name).should be_false
								end

								it 'should restore the old namespace module' do
									subject.load_module(parent_path, type, module_reference_name).should be_false
									Msf::Modules.const_defined?(relative_name).should be_true
									Msf::Modules.const_get(relative_name).should == @original_namespace_module
								end
							end

							context 'with usable metasploit_class' do
								before(:each) do
									# remove the mocked namespace_module since happy-path/real loading is occurring in this context
									subject.unstub(:namespace_module_transaction)
								end

								it 'should log load information' do
									subject.should_receive(:ilog).with(/#{module_reference_name}/, 'core', LEV_2)
									subject.load_module(parent_path, type, module_reference_name).should be_true
								end

								it 'should delete any pre-existing load errors from module_manager.module_load_error_by_path' do
									original_load_error = "Back in my day this module didn't load"
									module_manager.module_load_error_by_path[module_path] = original_load_error

									module_manager.module_load_error_by_path[module_path].should == original_load_error
									subject.load_module(parent_path, type, module_reference_name).should be_true
									module_manager.module_load_error_by_path[module_path].should be_nil
								end

								it 'should return true' do
									subject.load_module(parent_path, type, module_reference_name).should be_true
								end

								it 'should call module_manager.on_module_load' do
									module_manager.should_receive(:on_module_load)
									subject.load_module(parent_path, type, module_reference_name).should be_true
								end

								context 'with :recalculate_by_type' do
									it 'should set the type to be recalculated' do
										recalculate_by_type = {}

										subject.load_module(
												parent_path,
												type,
												module_reference_name,
												:recalculate_by_type => recalculate_by_type
										).should be_true
										recalculate_by_type[type].should be_true
									end
								end

								context 'with :count_by_type' do
									it 'should set the count to 1 if it does not exist' do
										count_by_type = {}

										count_by_type.has_key?(type).should be_false
										subject.load_module(
												parent_path,
												type,
												module_reference_name,
												:count_by_type => count_by_type
										).should be_true
										count_by_type[type].should == 1
									end

									it 'should increment the count if it does exist' do
										original_count = 1
										count_by_type = {
												type => original_count
										}

										subject.load_module(
												parent_path,
												type,
												module_reference_name,
												:count_by_type => count_by_type
										).should be_true

										incremented_count = original_count + 1
										count_by_type[type].should == incremented_count
									end
								end
							end
						end
					end
				end
			end
		end

		context '#create_namespace_module' do
			let(:namespace_module_names) do
				[
						'Msf',
						'Modules',
						relative_name
				]
			end

			let(:relative_name) do
				'Mod0'
			end

			before(:each) do
				# capture in local variable so it works in instance_eval
				relative_name = self.relative_name

				if Msf::Modules.const_defined? relative_name
					Msf::Modules.instance_eval do
						remove_const relative_name
					end
				end
			end

			it 'should wrap NAMESPACE_MODULE_CONTENT with module declarations matching namespace_module_names' do
				Object.should_receive(
						:module_eval
				).with(
						"module #{namespace_module_names[0]}\n" \
						"module #{namespace_module_names[1]}\n" \
						"module #{namespace_module_names[2]}\n" \
						"#{described_class::NAMESPACE_MODULE_CONTENT}\n" \
						"end\n" \
						"end\n" \
						"end",
						anything,
						anything
				)

				namespace_module = double('Namespace Module')
				namespace_module.stub(:loader=)
				subject.stub(:current_module => namespace_module)

				subject.send(:create_namespace_module, namespace_module_names)
			end

			it "should set the module_eval path to the loader's __FILE__" do
				Object.should_receive(
						:module_eval
				).with(
						anything,
						described_class_pathname.to_s,
						anything
				)

				namespace_module = double('Namespace Module')
				namespace_module.stub(:loader=)
				subject.stub(:current_module => namespace_module)

				subject.send(:create_namespace_module, namespace_module_names)
			end

			it 'should set the module_eval line to compensate for the wrapping module declarations' do
				Object.should_receive(
						:module_eval
				).with(
						anything,
						anything,
						described_class::NAMESPACE_MODULE_LINE - namespace_module_names.length
				)

				namespace_module = double('Namespace Module')
				namespace_module.stub(:loader=)
				subject.stub(:current_module => namespace_module)

				subject.send(:create_namespace_module, namespace_module_names)
			end

			it "should set the namespace_module's module loader to itself" do
				namespace_module = double('Namespace Module')

				namespace_module.should_receive(:loader=).with(subject)

				subject.stub(:current_module => namespace_module)

				subject.send(:create_namespace_module, namespace_module_names)
			end
		end

		context '#current_module' do
			let(:module_names) do
				[
						'Msf',
						'Modules',
						relative_name
				]
			end

			let(:relative_name) do
				'Mod0'
			end

			before(:each) do
				# copy to local variable so it is accessible in instance_eval
				relative_name = self.relative_name

				if Msf::Modules.const_defined? relative_name
					Msf::Modules.instance_eval do
						remove_const relative_name
					end
				end
			end

			it 'should return nil if the module is not defined' do
				Msf::Modules.const_defined?(relative_name).should be_false
				subject.send(:current_module, module_names).should be_nil
			end

			it 'should return the module if it is defined' do
				module Msf
					module Modules
						module Mod0
						end
					end
				end

				subject.send(:current_module, module_names).should == Msf::Modules::Mod0
			end
		end

		context '#each_module_reference_name' do
			it 'should be abstract' do
				expect {
					subject.send(:each_module_reference_name, parent_path)
				}.to raise_error(NotImplementedError)
			end
		end

		context '#module_path' do
			it 'should be abstract' do
				expect {
					subject.send(:module_path, parent_path, Msf::MODULE_AUX, module_reference_name)
				}.to raise_error(NotImplementedError)
			end
		end

		context '#module_path?' do
			it 'should return false if path is hidden' do
				hidden_path = '.hidden/path/file.rb'

				subject.send(:module_path?, hidden_path).should be_false
			end

			it 'should return false if the file extension is not MODULE_EXTENSION' do
				non_module_extension = '.c'
				path = "path/with/wrong/extension#{non_module_extension}"

				non_module_extension.should_not == described_class::MODULE_EXTENSION
				subject.send(:module_path?, path).should be_false
			end

			it 'should return false if the file is a unit test' do
				unit_test_extension = '.rb.ut.rb'
				path = "path/to/unit_test#{unit_test_extension}"

				subject.send(:module_path?, path).should be_false
			end

			it 'should return false if the file is a test suite' do
				test_suite_extension = '.rb.ts.rb'
				path = "path/to/test_suite#{test_suite_extension}"

				subject.send(:module_path?, path).should be_false
			end

			it 'should return true otherwise' do
				subject.send(:module_path?, module_path).should be_true
			end
		end

		context '#module_reference_name_from_path' do
			it 'should strip MODULE_EXTENSION from the end of the path' do
				path_without_extension = "a#{described_class::MODULE_EXTENSION}.dir/a"
				path = "#{path_without_extension}#{described_class::MODULE_EXTENSION}"

				subject.send(:module_reference_name_from_path, path).should == path_without_extension
			end
		end

		context '#namespace_module_name' do
			it 'should prefix the name with Msf::Modules::' do
				subject.send(:namespace_module_name, module_full_name).should start_with('Msf::Modules::')
			end

			it 'should prefix the relative name with Mod' do
				namespace_module_name = subject.send(:namespace_module_name, module_full_name)
				relative_name = namespace_module_name.gsub(/^.*::/, '')

				relative_name.should start_with('Mod')
			end

			it 'should be reversible' do
				namespace_module_name = subject.send(:namespace_module_name, module_full_name)
				unpacked_name = namespace_module_name.gsub(/^.*::Mod/, '')

				[unpacked_name].pack('H*').should == module_full_name
			end
		end

		context '#namespace_module_names' do
			it "should prefix the array with ['Msf', 'Modules']" do
				subject.send(:namespace_module_names, module_full_name).should start_with(['Msf', 'Modules'])
			end

			it 'should prefix the relative name with Mod' do
				namespace_module_names = subject.send(:namespace_module_names, module_full_name)

				namespace_module_names.last.should start_with('Mod')
			end

			it 'should be reversible' do
				namespace_module_names = subject.send(:namespace_module_names, module_full_name)
				relative_name = namespace_module_names.last
				unpacked_name = relative_name.gsub(/^Mod/, '')

				[unpacked_name].pack('H*').should == module_full_name
			end
		end

		context '#namespace_module_transaction' do
			let(:relative_name) do
				'Mod617578696c696172792f72737065632f6d6f636b'
			end

			context 'with pre-existing namespace module' do
				before(:each) do
					module Msf
						module Modules
							module Mod617578696c696172792f72737065632f6d6f636b
								class Metasploit3

								end
							end
						end
					end

					@existent_namespace_module = Msf::Modules::Mod617578696c696172792f72737065632f6d6f636b
				end

				context 'with :reload => false' do
					it 'should log an error' do
						subject.should_receive(:elog).with(/Reloading.*when :reload => false/)

						subject.send(:namespace_module_transaction, module_full_name, :reload => false) do |namespace_module|
							true
						end
					end
				end

				it 'should remove the pre-existing namespace module' do
					Msf::Modules.should_receive(:remove_const).with(relative_name)

					subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
						true
					end
				end

				it 'should create a new namespace module for the block' do
					subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
						namespace_module.should_not == @existent_namespace_module

						expect {
							namespace_module::Metasploit3
						}.to raise_error(NameError)

						true
					end
				end

				context 'with an Exception from the block' do
					let(:error_class) do
						NameError
					end

					let(:error_message) do
						"SayMyName"
					end

					it 'should restore the previous namespace module' do
						Msf::Modules.const_get(relative_name).should == @existent_namespace_module

						begin
							subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
								current_constant = Msf::Modules.const_get(relative_name)

								current_constant.should == namespace_module
								current_constant.should_not == @existent_namespace_module

								raise error_class, error_message
							end
						rescue error_class => error
						end

						Msf::Modules.const_get(relative_name).should == @existent_namespace_module
					end

					it 'should re-raise the error' do
						expect {
							subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
								raise error_class, error_message
							end
						}.to raise_error(error_class, error_message)
					end
				end

				context 'with the block returning false' do
					it 'should restore the previous namespace module' do
						Msf::Modules.const_get(relative_name).should == @existent_namespace_module

						subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
							current_constant = Msf::Modules.const_get(relative_name)

							current_constant.should == namespace_module
							current_constant.should_not == @existent_namespace_module

							false
						end

						Msf::Modules.const_get(relative_name).should == @existent_namespace_module
					end

					it 'should return false' do
						subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
							false
						}.should be_false
					end
				end

				context 'with the block returning true' do
					it 'should not restore the previous namespace module' do
						Msf::Modules.const_get(relative_name).should == @existent_namespace_module

						subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
							true
						end

						current_constant = Msf::Modules.const_get(relative_name)

						current_constant.should_not be_nil
						current_constant.should_not == @existent_namespace_module
					end

					it 'should return true' do
						subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
							true
						}.should be_true
					end
				end
			end

			context 'without pre-existing namespace module' do
				before(:each) do
					relative_name = self.relative_name

					if Msf::Modules.const_defined? relative_name
						Msf::Modules.send(:remove_const, relative_name)
					end
				end

        it 'should create a new namespace module' do
					expect {
						Msf::Modules.const_get(relative_name)
					}.to raise_error(NameError)

					subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
						Msf::Modules.const_get(relative_name).should == namespace_module
					end
        end

				context 'with an Exception from the block' do
					let(:error_class) do
						Exception
					end

					let(:error_message) do
						'Error Message'
					end

					it 'should remove the created namespace module' do
						Msf::Modules.const_defined?(relative_name).should be_false

						begin
							subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
								Msf::Module.const_defined?(relative_name).should be_true

								raise error_class, error_message
							end
						rescue error_class
						end

						Msf::Modules.const_defined?(relative_name).should be_false
					end

					it 'should re-raise the error' do
						expect {
							subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
								raise error_class, error_message
							end
						}.to raise_error(error_class, error_message)
					end
				end

				context 'with the block returning false' do
					it 'should remove the created namespace module' do
						Msf::Modules.const_defined?(relative_name).should be_false

						subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
							Msf::Modules.const_defined?(relative_name).should be_true

							false
						end

						Msf::Modules.const_defined?(relative_name).should be_false
					end

					it 'should return false' do
						subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
							false
						}.should be_false
					end
				end

				context 'with the block returning true' do
					it 'should not restore the non-existent previous namespace module' do
						Msf::Modules.const_defined?(relative_name).should be_false

						created_namespace_module = nil

						subject.send(:namespace_module_transaction, module_full_name) do |namespace_module|
							Msf::Modules.const_defined?(relative_name).should be_true

							created_namespace_module = namespace_module

							true
						end

						Msf::Modules.const_defined?(relative_name).should be_true
						Msf::Modules.const_get(relative_name).should == created_namespace_module
					end

					it 'should return true' do
						subject.send(:namespace_module_transaction, module_full_name) { |namespace_module|
							true
						}.should be_true
					end
				end
			end
		end

		context '#read_module_content' do
			it 'should be abstract' do
				type = Msf::MODULE_AUX

				expect {
					subject.send(:read_module_content, parent_pathname.to_s, type, module_reference_name)
				}.to raise_error(NotImplementedError)
			end
		end

		context '#restore_namespace_module' do
			let(:parent_module) do
				Msf::Modules
			end

			let(:relative_name) do
				'Mod0'
			end

			it 'should do nothing if parent_module is nil' do
				parent_module = nil

				# can check that NoMethodError is not raised because *const* methods are
				# not defined on `nil`.
				expect {
					subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)
				}.to_not raise_error
			end

			context 'with namespace_module nil' do
				let(:namespace_module) do
					nil
				end

				it 'should remove relative_name' do
					parent_module.should_receive(:remove_const).with(relative_name)

					subject.send(:restore_namespace_module, parent_module, relative_name, namespace_module)
				end

				it 'should not set the relative_name constant to anything' do
					parent_module.should_not_receive(:const_set)

					subject.send(:restore_namespace_module, parent_module, relative_name, namespace_module)
				end
			end

			context 'with parent_module and namespace_module' do
				before(:each) do
					module Msf
						module Modules
							module Mod0
								class Metasploit3

								end
							end
						end
					end

					@original_namespace_module = Msf::Modules::Mod0

					Msf::Modules.send(:remove_const, relative_name)
				end

				context 'with relative_name being a defined constant' do
					before(:each) do
						module Msf
							module Modules
								module Mod0
									class Metasploit2

									end
								end
							end
						end

						@current_namespace_module = Msf::Modules::Mod0
					end

					context 'with the current constant being the namespace_module' do
						it 'should not change the constant' do
							parent_module.const_defined?(relative_name).should be_true

							current_module = parent_module.const_get(relative_name)
							current_module.should == @current_namespace_module

							subject.send(:restore_namespace_module, parent_module, relative_name, @current_namespace_module)

							parent_module.const_defined?(relative_name).should be_true
							restored_module = parent_module.const_get(relative_name)
							restored_module.should == current_module
							restored_module.should == @current_namespace_module
						end

						it 'should not remove the constant and then set it' do
							parent_module.should_not_receive(:remove_const).with(relative_name)
							parent_module.should_not_receive(:const_set).with(relative_name, @current_namespace_module)

							subject.send(:restore_namespace_module, parent_module, relative_name, @current_namespace_module)
						end
					end

					context 'without the current constant being the namespace_module' do
						it 'should remove relative_name from parent_module' do
							parent_module.const_defined?(relative_name).should be_true
							parent_module.should_receive(:remove_const).with(relative_name)

							subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)
						end

						it 'should restore the module to the constant' do
							parent_module.const_get(relative_name).should_not == @original_namespace_module

							subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)

							parent_module.const_get(relative_name).should == @original_namespace_module
						end
					end
				end

				context 'without relative_name being a defined constant' do
					it 'should set relative_name on parent_module to namespace_module' do
						parent_module.const_defined?(relative_name).should be_false

						subject.send(:restore_namespace_module, parent_module, relative_name, @original_namespace_module)

						parent_module.const_defined?(relative_name).should be_true
						parent_module.const_get(relative_name).should == @original_namespace_module
					end
				end
			end
		end

		context '#typed_path' do
      it 'should delegate to the class method' do
				type = Msf::MODULE_EXPLOIT

				described_class.should_receive(:typed_path).with(type, module_reference_name)
				subject.send(:typed_path, type, module_reference_name)
      end
		end

		context '#usable?' do
			context 'without metasploit_class responding to is_usable' do
				it 'should return true' do
					metasploit_class = double('Metasploit Class')
					metasploit_class.should_not respond_to(:is_usable)

					subject.send(:usable?, metasploit_class).should be_true
				end
			end

			context 'with metasploit_class responding to is_usable' do
				it 'should delegate to metasploit_class.is_usable' do
					# not a proper return, but guarantees that delegation is actually happening
					usability = 'maybe'
					metasploit_class = double('Metasploit Class', :is_usable => usability)

					subject.send(:usable?, metasploit_class).should == usability
				end

				context 'with error from metasploit_class.is_usable' do
					let(:error) do
						'Expected error'
					end

					let(:metasploit_class) do
						metasploit_class = double('Metasploit Class')

						metasploit_class.stub(:is_usable).and_raise(error)

						metasploit_class
					end

					it 'should log error' do
						subject.should_receive(:elog).with(/#{error}/)

						subject.send(:usable?, metasploit_class)
					end

					it 'should return false' do
						subject.send(:usable?, metasploit_class).should be_false
					end
				end
			end
		end
	end
end
