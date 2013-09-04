require 'spec_helper'

describe Metasploit::Framework::Module::PathSet::Database do
	include_context 'DatabaseCleaner'

	subject(:path_set) do
		described_class.new(
				:cache => cache
		)
	end

	let(:cache) do
		double('Metasploit::Framework::Module::Cache')
	end

	context '#add' do
		subject(:add) do
			path_set.add(real_path, :gem => gem, :name => name)
		end

		let(:gem) do
			nil
		end

		let(:name) do
			nil
		end

		let(:real_path) do
			nil
		end

		it 'should validate Mdm::Module::Path using :add context' do
			Mdm::Module::Path.any_instance.should_receive(:valid?).with(:add).and_call_original

			expect {
				add
			}.to raise_error ActiveRecord::RecordInvalid
		end

		context 'with valid for :add' do
			context 'with 0 collisions' do
				let!(:non_colliding) do
					FactoryGirl.create(:mdm_module_path)
				end

				let(:gem) do
					FactoryGirl.generate :metasploit_model_module_path_gem
				end

				let(:name) do
					FactoryGirl.generate :metasploit_model_module_path_name
				end

				let(:real_path) do
					FactoryGirl.generate :metasploit_model_module_path_real_path
				end

        it 'should create a new Mdm::Module::Path' do
					expect {
						add
					}.to change(Mdm::Module::Path, :count).by(1)
				end
			end

			context 'with 1 collision' do
				let!(:collision) do
					FactoryGirl.create(:named_mdm_module_path)
				end

				context 'with (gem, name) collision' do
					let(:gem) do
						collision.gem
					end

					let(:name) do
						collision.name
					end

					let(:real_path) do
						FactoryGirl.generate :metasploit_model_module_path_real_path
					end

					it 'should update real_path for collision' do
						expect {
							add
						}.to change {
							# use find to reload before and after
							Mdm::Module::Path.find(collision.id).real_path
						}.to(real_path)
					end

					it 'should return the updated collision as the added path' do
						add.should == collision
					end
				end

				context 'with real_path collision' do
					let(:gem) do
						FactoryGirl.generate :metasploit_model_module_path_gem
					end

					let(:name) do
						FactoryGirl.generate :metasploit_model_module_path_name
					end

					let(:real_path) do
						collision.real_path
					end

					it 'should update gem for collision' do
						expect {
							add
						}.to change {
							# use find to reload before and after
							Mdm::Module::Path.find(collision.id).gem
						}.to(gem)
					end

					it 'should update name for collision' do
						expect {
							add
						}.to change {
							# use find to reload before and after
							Mdm::Module::Path.find(collision.id).name
						}.to(name)
					end

					it 'should return the updated collision as the added path' do
						add.should == collision
					end
				end

				context 'with (gem, name) and real_path collision' do
					let(:gem) do
						collision.gem
					end

					let(:name) do
						collision.name
					end

					let(:real_path) do
						collision.real_path
					end

					it 'should not create a Mdm::Module::Path' do
						expect {
							add
						}.to_not change(Mdm::Module::Path, :count)
					end

					it 'return collision' do
						add.should == collision
					end
				end
			end

			context 'with 2 collisions' do
				let(:gem) do
					name_collision.gem
				end

				let(:name) do
					name_collision.name
				end

				let(:real_path) do
					real_path_collision.real_path
				end

				let!(:name_collision) do
					FactoryGirl.create(:named_mdm_module_path)
				end

				let!(:real_path_collision) do
					FactoryGirl.create(
							:mdm_module_path,
							:gem => nil,
							:name => nil
					)
				end

				it 'should raise Metasploit::Framework::Module::PathSet::Error' do
					expect {
						add
					}.to raise_error(Metasploit::Framework::Module::PathSet::Error)
				end
			end
		end

		context 'without valid for :add' do
			it 'should raise ActiveRecord::RecordInvalid' do
				expect {
					add
				}.to raise_error(ActiveRecord::RecordInvalid)
			end
		end
	end
end