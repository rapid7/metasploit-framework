# -*- coding:binary -*-
require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::Namespace do
	let(:module_path) do
		"parent/path/type_directory/#{module_reference_name}.rb"
	end

	let(:module_reference_name) do
		'module/reference/name'
	end

	subject do
		mod = Module.new
		mod.extend described_class

	  mod
	end

	context 'metasploit_class' do
		before(:each) do
			if major
				subject.const_set("Metasploit#{major}", Class.new)
			end
		end

		context 'without Metasploit<n> constant defined' do
			let(:major) do
				nil
			end

      it 'should not be defined' do
	      metasploit_constants = subject.constants.select { |constant|
		      constant.to_s =~ /Metasploit/
	      }

	      metasploit_constants.should be_empty
      end
		end

		context 'with Metasploit1 constant defined' do
			let(:major) do
				1
			end

			it 'should be defined' do
				subject.const_defined?('Metasploit1').should be_true
			end

			it 'should return the class' do
				subject.metasploit_class.should be_a Class
			end
		end

		context 'with Metasploit2 constant defined' do
			let(:major) do
				2
			end

			it 'should be defined' do
				subject.const_defined?('Metasploit2').should be_true
			end

			it 'should return the class' do
				subject.metasploit_class.should be_a Class
			end
		end

		context 'with Metasploit3 constant defined' do
			let(:major) do
				3
			end

			it 'should be defined' do
				subject.const_defined?('Metasploit3').should be_true
			end

			it 'should return the class' do
				subject.metasploit_class.should be_a Class
			end
		end

		context 'with Metasploit4 constant defined' do
			let(:major) do
				4
			end

			it 'should be defined' do
				subject.const_defined?('Metasploit4').should be_true
			end

			it 'should return the class' do
				subject.metasploit_class.should be_a Class
			end
		end

		context 'with Metasploit5 constant defined' do
			let(:major) do
				5
			end

			it 'should be defined' do
				subject.const_defined?('Metasploit5').should be_true
			end

			it 'should be newer than Msf::Framework::Major' do
				major.should > Msf::Framework::Major
			end

			it 'should return nil' do
				subject.metasploit_class.should be_nil
			end
		end
	end

	context 'metasploit_class!' do
		it 'should call metasploit_class' do
			subject.should_receive(:metasploit_class).and_return(Class.new)

			subject.metasploit_class!(module_path, module_reference_name)
		end

		context 'with metasploit_class' do
			let(:metasploit_class) do
				Class.new
			end

			before(:each) do
				subject.stub(:metasploit_class => metasploit_class)
			end

			it 'should return the metasploit_class' do
				subject.metasploit_class!(module_path, module_reference_name).should == metasploit_class
			end
		end

		context 'without metasploit_class' do
			before(:each) do
				subject.stub(:metasploit_class => nil)
			end

			it 'should raise a Msf::Modules::MetasploitClassCompatibilityError' do
				expect {
					subject.metasploit_class!(module_path, module_reference_name)
				}.to raise_error(Metasploit::Framework::Module::Ancestor::Error::MetasploitModuleIncompatibility)
			end

			context 'the Msf::Modules::MetasploitClassCompatibilityError' do
				it 'should include the module path' do
					error = nil

					begin
						subject.metasploit_class!(module_path, module_reference_name)
					rescue Metasploit::Framework::Module::Ancestor::Error::MetasploitModuleIncompatibility => error
					end

					error.should_not be_nil
					error.to_s.should include(module_path)
				end

				it 'should include the module reference name' do
					error = nil

					begin
						subject.metasploit_class!(module_path, module_reference_name)
					rescue Metasploit::Framework::Module::Ancestor::Error::MetasploitModuleIncompatibility => error
					end

					error.should_not be_nil
					error.to_s.should include(module_reference_name)
				end
			end
		end
	end

	context 'version_compatible!' do
		context 'without RequiredVersions' do
			it 'should not be defined' do
				subject.const_defined?('RequiredVersions').should be_false
			end

			it 'should not raise an error' do
				expect {
					subject.version_compatible!(module_path, module_reference_name)
				}.to_not raise_error
			end
		end

		context 'with RequiredVersions defined' do
			let(:minimum_api_version) do
				1
			end

			let(:minimum_core_version) do
				1
			end

			before(:each) do
				subject.const_set(
						:RequiredVersions,
						[
								minimum_core_version,
								minimum_api_version
						]
				)
			end

			context 'with minimum Core version' do
				it 'should be <= Msf::Framework::VersionCore' do
					minimum_core_version.should <= Msf::Framework::VersionCore
				end

				context 'without minimum API version' do
					let(:minimum_api_version) do
						2
					end

					it 'should be > Msf::Framework::VersionAPI' do
						minimum_api_version.should > Msf::Framework::VersionAPI
					end

					it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Error::VersionIncompatibility'
				end

				context 'with minimum API version' do
					it 'should not raise an error' do
						expect {
							subject.version_compatible!(module_path, module_reference_name)
						}.to_not raise_error(Metasploit::Framework::Module::Ancestor::Error::VersionIncompatibility)
					end
				end
			end

			context 'without minimum Core version' do
				let(:minimum_core_version) do
					5
				end

				it 'should be > Msf::Framework::VersionCore' do
					minimum_core_version.should > Msf::Framework::VersionCore
				end

				context 'without minimum API version' do
					let(:minimum_api_version) do
						2
					end

					it 'should be > Msf::Framework::VersionAPI' do
						minimum_api_version.should > Msf::Framework::VersionAPI
					end

					it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Error::VersionIncompatibility'
				end

				context 'with minimum API version' do
					it 'should be <= Msf::Framework::VersionAPI' do
						minimum_api_version <= Msf::Framework::VersionAPI
					end

					it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Error::VersionIncompatibility'
				end
			end
		end
	end
end
