require 'spec_helper'

describe Metasploit::Framework::Module::PathSet::Memory do
	subject(:path_set) do
		described_class.new(
				:cache => cache
		)
	end

	let(:cache) do
		double('Metasploit::Framework::Module:Cache')
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

		it 'should validate Metasploit::Framework::Module::Path' do
			Metasploit::Framework::Module::Path.any_instance.should_receive(:valid?).and_call_original

			expect {
				add
			}.to raise_error Metasploit::Framework::ModelInvalid
		end

		it 'should set path_set after validating' do
			path = FactoryGirl.build(:unnamed_metasploit_framework_module_path)
			Metasploit::Framework::Module::Path.stub(:new => path)

			path.should_receive(:valid?).ordered.and_return(true)
			path.should_receive(:path_set=).with(path_set).ordered.and_call_original
			# stub save to prevent save!'s call to valid? from counting for this test
			path.stub(:save!)

			add
		end

		context 'with valid' do
			context 'with (gem, name) and real_path collision' do
				context 'with 1 other Metasploit::Framework::Module::Path' do
					let(:gem) do
						collision.gem
					end

					let(:name) do
						collision.name
					end

					let(:real_path) do
						collision.real_path
					end

					let(:collision) do
						FactoryGirl.build(:named_metasploit_framework_module_path)
					end

					before(:each) do
						path_set.path_by_real_path[collision.real_path] = collision

						path_by_name = path_set.path_by_name_by_gem[collision.gem]
						path_by_name[collision.name] = collision
					end

					it 'should return collision' do
						add.should == collision
					end
				end

				context 'with 2 other Metasploit::Framework::Module::Paths' do
					let(:gem) do
						name_collision.gem
					end

					let(:name) do
						name_collision.name
					end

					let(:name_collision) do
						FactoryGirl.build(:named_metasploit_framework_module_path)
					end

					let(:real_path) do
						real_path_collision.real_path
					end

					let(:real_path_collision) do
						FactoryGirl.build(:unnamed_metasploit_framework_module_path)
					end

					before(:each) do
						path_set.path_by_real_path[real_path_collision.real_path] = real_path_collision

						path_by_name = path_set.path_by_name_by_gem[name_collision.gem]
						path_by_name[name_collision.name] = name_collision
					end

					it 'should raise Metasploit::Framework::Module::PathSet::Error' do
						expect {
							add
						}.to raise_error Metasploit::Framework::Module::PathSet::Error
					end
				end
			end

			context 'with (gem, name) collision' do
				let(:gem) do
					name_collision.gem
				end

				let(:name) do
					name_collision.name
				end

				let(:name_collision) do
					FactoryGirl.build(:named_metasploit_framework_module_path)
				end

				let(:real_path) do
					FactoryGirl.generate :metasploit_framework_module_path_real_path
				end

				before(:each) do
					name_collision.path_set = path_set

					path_set.path_by_real_path[name_collision.real_path] = name_collision

					path_by_name = path_set.path_by_name_by_gem[name_collision.gem]
					path_by_name[name_collision.name] = name_collision

					# clear changes so change? logic in save! works correctly
					name_collision.instance_variable_get(:@changed_attributes).clear
				end

				it 'should remove old real_path' do
					old_real_path = name_collision.real_path

					add

					path_set.path_by_real_path.should_not have_key(old_real_path)
				end

				it 'should update real_path on collision' do
					expect {
						add
					}.to change(name_collision, :real_path).to(real_path)
				end

				it 'should add new real_path' do
					add

					path_set.path_by_real_path.should have_key(real_path)
				end

				it 'should update #module_ancestors real_paths' do
					name_collision.should_receive(:update_module_ancestor_real_paths)

					add
				end

				it 'should return collision' do
					add.should == name_collision
				end
			end

			context 'with real_path collision' do
				let(:real_path) do
					real_path_collision.real_path
				end

				before(:each) do
					real_path_collision.path_set = path_set

					path_set.path_by_real_path[real_path_collision.real_path] = real_path_collision

					if real_path_collision.named?
						path_by_name = path_set.path_by_name_by_gem[real_path_collision.gem]
						path_by_name[real_path_collision.name] = real_path_collision
					end

					# clear changes so that change? logic in save! works correctly
					real_path_collision.instance_variable_get(:@changed_attributes).clear
				end

				context 'with named collision' do
					let(:real_path_collision) do
						FactoryGirl.build(:named_metasploit_framework_module_path)
					end

					context 'with named path' do
						let(:gem) do
							FactoryGirl.generate :metasploit_framework_module_path_gem
						end

						let(:name) do
							FactoryGirl.generate :metasploit_framework_module_path_name
						end

						it 'should remove old name entry' do
							old_gem = real_path_collision.gem
							old_name = real_path_collision.name

							add

							path_by_name = path_set.path_by_name_by_gem[old_gem]
							path_by_name.should_not have_key(old_name)
						end

						it "should update change collision's (gem, name)" do
							expect {
								add
							}.to change {
								[
										real_path_collision.gem,
										real_path_collision.name
								]
							}.to(
											 [
													 gem,
													 name
											 ]
									 )
						end

						it 'should add new name entry' do
							add

							path_by_name = path_set.path_by_name_by_gem[gem]
							path_by_name[name].should == real_path_collision
						end

						it 'should return real_path_collision' do
							add.should == real_path_collision
						end
					end

					context 'with unnamed path' do
						it 'should not remove old name entry' do
							old_gem = real_path_collision.gem
							old_name = real_path_collision.name

							add

							path_by_name = path_set.path_by_name_by_gem[old_gem]
							path_by_name.should have_key(old_name)
						end

						it "should not change collision's (gem, name)" do
							expect {
								add
							}.to_not change {
								[
										real_path_collision.gem,
										real_path_collision.name
								]
							}
						end

						it 'should return real_path_collision' do
							add.should == real_path_collision
						end
					end
				end

				context 'with unnamed collision' do
					let(:real_path_collision) do
						FactoryGirl.build(:unnamed_metasploit_framework_module_path)
					end

					context 'with named path' do
						let(:gem) do
							FactoryGirl.generate :metasploit_framework_module_path_gem
						end

						let(:name) do
							FactoryGirl.generate :metasploit_framework_module_path_name
						end

						it "should update change collision's (gem, name)" do
							expect {
								add
							}.to change {
								[
										real_path_collision.gem,
										real_path_collision.name
								]
							}.to(
											 [
													 gem,
													 name
											 ]
									 )
						end

						it 'should add new name entry' do
							add

							path_by_name = path_set.path_by_name_by_gem[gem]
							path_by_name[name].should == real_path_collision
						end

						it 'should return real_path_collision' do
							add.should == real_path_collision
						end
					end

					context 'with unnamed path' do
						it 'should return real_path_collision' do
							add.should == real_path_collision
						end
					end
				end
			end

			context 'without collision' do
				let(:real_path) do
					FactoryGirl.generate :metasploit_framework_module_path_real_path
				end

				context 'with named path' do
					let(:gem) do
						FactoryGirl.generate :metasploit_framework_module_path_gem
					end

					let(:name) do
						FactoryGirl.generate :metasploit_framework_module_path_name
					end

					it 'should add name entry' do
						add

						path_by_name = path_set.path_by_name_by_gem[gem]
						path_by_name[name].should be_a Metasploit::Framework::Module::Path
					end

					it 'should add real_path entry' do
						add

						path_set.path_by_real_path[real_path].should be_a Metasploit::Framework::Module::Path
					end

					it 'should return new path' do
						add.should be_a Metasploit::Framework::Module::Path
					end
				end

				context 'without named path' do
					it 'should add real_path entry' do
						add

						path_set.path_by_real_path[real_path].should be_a Metasploit::Framework::Module::Path
					end

					it 'should return new path' do
						add.should be_a Metasploit::Framework::Module::Path
					end
				end
			end
		end

		context 'without valid' do
			it 'should raise Metasploit::Framework::Module::Path::Invalid' do
				expect {
					add
				}.to raise_error Metasploit::Framework::ModelInvalid
			end
		end
	end
end