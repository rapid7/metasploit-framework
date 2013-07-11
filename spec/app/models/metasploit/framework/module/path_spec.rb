require 'spec_helper'

describe Metasploit::Framework::Module::Path do
	it { should be_a ActiveModel::Dirty }

	it_should_behave_like 'Metasploit::Model::Module::Path' do
		let(:path_class) do
			described_class
		end
	end

  context 'attribute methods' do
		it_should_behave_like 'change tracking for', :gem
		it_should_behave_like 'change tracking for', :name
		it_should_behave_like 'change tracking for', :real_path
	end

	context 'factories' do
		context 'metasploit_framework_module_path' do
			subject(:metasploit_framework_module_path) do
				FactoryGirl.build(:metasploit_framework_module_path)
			end

			it { should be_valid }
		end

		context 'named_metasploit_framework_module_path' do
			subject(:named_metasploit_framework_module_path) do
				FactoryGirl.build(:named_metasploit_framework_module_path)
			end

			it { should be_valid }

			its(:gem) { should_not be_nil }
			its(:name) { should_not be_nil }
		end

		context 'unnamed_metasploit_framework_module_path' do
			subject(:unnamed_metasploit_framework_module_path) do
				FactoryGirl.build(:unnamed_metasploit_framework_module_path)
			end

			it { should be_valid }

			its(:gem) { should be_nil }
			its(:name) { should be_nil }
		end
	end

	context '#update_module_ancestor_real_paths' do
		let(:path) do
			FactoryGirl.build(:metasploit_framework_module_path)
		end

		let(:new_real_path) do
			FactoryGirl.generate :metasploit_framework_module_path_real_path
		end

		context 'with #module_ancestors' do
			let!(:ancestors) do
				FactoryGirl.build_list(:metasploit_framework_module_ancestor, 2, :parent_path => path)
			end

			before(:each) do
				# Have to remove new_real_path sas sequence will have already created it
				FileUtils.rmdir(new_real_path)
				# Move old real_path to new real_path to simulate install location for
				# path changing and to ensure that ancestors actually exist on path.
				FileUtils.mv(path.real_path, new_real_path)

				path.real_path = new_real_path
			end

			it { path.should be_valid }

			it "should update module_ancestor's real_paths" do
				expect {
					path.update_module_ancestor_real_paths
				}.to change {
					path.module_ancestors.map(&:real_path)
				}
			end
		end
	end
end