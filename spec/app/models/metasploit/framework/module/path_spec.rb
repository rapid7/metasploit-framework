require 'spec_helper'

describe Metasploit::Framework::Module::Path do
	it { should be_a ActiveModel::Dirty }

	it_should_behave_like 'Metasploit::Model::Module::Path' do
		let(:path_class) do
			described_class
		end

		let(:path_factory) do
			:metasploit_framework_module_path
		end
	end

	context 'attribute methods' do
		subject(:path) do
			# use named path so that valid paths will be created in shared examples
			FactoryGirl.build(:named_metasploit_framework_module_path)
		end

		before(:each) do
			# reset changes from FactoryGirl
			path.instance_variable_get(:@changed_attributes).clear

			# assign to a path_set so that save! won't error out
			path.path_set = Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
		end

		it_should_behave_like 'change tracking for', :gem
		it_should_behave_like 'change tracking for', :name
		it_should_behave_like 'change tracking for', :real_path do
			before(:each) do
				new_real_path = "#{path.real_path}_changed"
				FileUtils.mkdir_p(new_real_path)
			end
		end
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

	context '#name_collision' do
		subject(:name_collision) do
			path.name_collision
		end

		context 'with path_set' do
			let(:original_path) do
				FactoryGirl.build(
						:metasploit_framework_module_path,
						:gem => gem,
						:name => name
				)
			end

			let(:path_set) do
				Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
			end

			before(:each) do
				original_path.path_set = path_set
				path_by_name = path_set.path_by_name_by_gem[original_path.gem]
				path_by_name[original_path.name] = original_path

				path.path_set = path_set
			end

			context 'with named' do
				let(:path) do
					FactoryGirl.build(:named_metasploit_framework_module_path)
				end

				context 'with same gem' do
					let(:gem) do
						path.gem
					end

					context 'with same name' do
						let(:name) do
							path.name
						end

						it 'should return collision' do
							name_collision.should == original_path
						end
					end

					context 'without same name' do
						let(:name) do
							FactoryGirl.generate :metasploit_framework_module_path_name
						end

						it { should be_nil }
					end
				end

				context 'without same gem' do
					let(:gem) do
						FactoryGirl.generate :metasploit_framework_module_path_gem
					end

					context 'with same name' do
						let(:name) do
							path.name
						end

						it { should be_nil }
					end

					context 'without same name' do
						let(:name) do
							FactoryGirl.generate :metasploit_framework_module_path_name
						end

						it { should be_nil }
					end
				end
			end

			context 'without named' do
				let(:path) do
					FactoryGirl.build(:unnamed_metasploit_framework_module_path)
				end
			end
		end

		context 'without path_set' do
			context 'with named' do
				let(:path) do
					FactoryGirl.build(:named_metasploit_framework_module_path)
				end

				it 'should raise Metasploit::Framework::Module::Path::Error' do
					expect {
						name_collision
					}.to raise_error(Metasploit::Framework::Module::Path::Error)
				end
			end

			context 'with unnamed' do
				let(:path) do
					FactoryGirl.build(:unnamed_metasploit_framework_module_path)
				end

				it { should be_nil }
			end
		end
	end

	context '#path_set' do
		subject(:path_set) do
			path.path_set
		end

		let(:path) do
			FactoryGirl.build(:metasploit_framework_module_path)
		end

		context 'with value' do
			let(:value) do
				Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
			end

			before(:each) do
				path.path_set = value
			end

			it 'should return value' do
				path_set.should == value
			end
		end

		context 'without value' do
			it 'should raise Metasploit::Framework::Module::Path::Error' do
				expect {
					path_set
				}.to raise_error Metasploit::Framework::Module::Path::Error
			end
		end
	end

	context '#path_set=' do
		subject(:path) do
			FactoryGirl.build(:metasploit_framework_module_path)
		end

		let(:new_path_set) do
			Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
		end

		context 'with undefined' do
			it 'should set @path_set' do
				expect {
					path.path_set = new_path_set
				}.to change {
					path.instance_variable_get(:@path_set)
				}.to(new_path_set)
			end
		end

		context 'without undefined' do
			let(:original_path_set) do
				Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
			end

			before(:each) do
				path.path_set = original_path_set
			end

			it 'should raise Metasploit::Framework::Module::Path::Error' do
				expect {
					path.path_set = new_path_set
				}.to raise_error Metasploit::Framework::Module::Path::Error
			end
		end
	end

	context '#real_path_collision' do
		subject(:real_path_collision) do
			path.real_path_collision
		end

		let(:path) do
			FactoryGirl.build(:metasploit_framework_module_path)
		end

		context 'with path_set' do
			let(:path_set) do
				Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
			end

			before(:each) do
				path.path_set = path_set
			end

			context 'with collision' do
				let(:collision) do
					FactoryGirl.build(
							:metasploit_framework_module_path,
							:real_path => path.real_path
					)
				end

				before(:each) do
					collision.path_set = path_set
					path_set.path_by_real_path[collision.real_path] = collision
				end

				it 'should return collision' do
					real_path_collision.should == collision
				end
			end

			context 'without collision' do
				it { should be_nil }
			end
		end

		context 'without path_set' do
			it 'should raise Metasploit::Framework::Module::Path::Error' do
				expect {
					real_path_collision
				}.to raise_error(Metasploit::Framework::Module::Path::Error)
			end
		end
	end

	context '#save!' do
		subject(:save!) do
			path.save!
		end

		context 'with valid' do
			let(:path) do
				FactoryGirl.build(:metasploit_framework_module_path, :path_set => path_set)
			end

			let(:path_set) do
				Metasploit::Framework::Module::PathSet::Memory.new(:framework => nil)
			end

			it 'should run save callbacks after validation' do
				# stub valid so run_callbacks isn't called with :validation.
				path.stub(:valid? => true)
				path.should_receive(:run_callbacks).with(:save)

				save!
			end

			it 'should save changes to @previous_changes after running save callbacks' do
				# stub valid so run_callbacks isn't called with :validation.
				path.stub(:valid? => true)
				path.should_receive(:run_callbacks).with(:save).ordered
				path.should_receive(:changes).ordered.and_call_original

				path.previous_changes.should be_nil

				save!

				path.previous_changes.should_not be_empty
			end

			it 'should clear changes after running save callbacks' do
				# changes from FactoryGirl
				# check before adding message expectation on changes
				path.changes.should_not be_empty

				# stub valid so run_callbacks isn't called with :validation.
				path.stub(:valid? => true)
				path.should_receive(:run_callbacks).with(:save).ordered
				# once in save!
				path.should_receive(:changes).ordered
				# once in this example
				path.should_receive(:changes).ordered

				save!

				path.changes.should be_nil
			end

			context '(gem, name)' do
				before(:each) do
					path.gem = gem_was
					path.name = name_was

					if path.named?
						# populate cache so deletion can be detected
						path_by_name = path_set.path_by_name_by_gem[path.gem]
						path_by_name[path.name] = path
					end

					path.changed_attributes.clear

					path.gem = gem
					path.name = name
				end

				context 'with gem changed' do
					let(:gem) do
						FactoryGirl.generate :metasploit_framework_module_path_gem
					end

					context 'with name changed' do
						let(:name) do
							FactoryGirl.generate :metasploit_framework_module_path_name
						end

						context 'with gem_was blank' do
							let(:gem_was) do
								nil
							end

							let(:name_was) do
								FactoryGirl.generate :metasploit_framework_module_path_name
							end

							it 'should not look up path_by_name in path_set.path_by_name_by_gem' do
								path_set.path_by_name_by_gem.should_not_receive(:[]).with(gem_was)
								path_set.path_by_name_by_gem.should_receive(:[]).with(gem).and_call_original

								save!
							end

							it 'should add path to path_set.path_by_name_by_gem' do
								save!

								path_by_name = path_set.path_by_name_by_gem[gem]
								path_by_name[name].should == path
							end
						end

						context 'without gem_was blank' do
							let(:gem_was) do
								FactoryGirl.generate :metasploit_framework_module_path_gem
							end

							context 'with name_was blank' do
								let(:name_was) do
									nil
								end

							  it 'should not look up path_by_name in path_set.path_by_name_by_gem' do
									path_set.path_by_name_by_gem.should_not_receive(:[]).with(gem_was)
									path_set.path_by_name_by_gem.should_receive(:[]).with(gem).and_call_original

									save!
								end

								it 'should add path to path_set.path_by_name_by_gem' do
									save!

									path_by_name = path_set.path_by_name_by_gem[gem]
									path_by_name[name].should == path
								end
							end

							context 'without name_was blank' do
								let(:name_was) do
									FactoryGirl.generate :metasploit_framework_module_path_name
								end

								it 'should delete name_was from path_set.path_by_name_by_gem' do
									expect {
										save!
									}.to change {
										path_set.path_by_name_by_gem[gem_was].has_key?(name_was)
									}.to(false)
								end

								it 'should add path to path_set.path_by_name_by_gem' do
									save!

									path_by_name = path_set.path_by_name_by_gem[gem]
									path_by_name[name].should == path
								end
							end
						end
					end

					context 'without name changed' do
						let(:name) do
							name_was
						end

						context 'without gem_was blank' do
							let(:gem_was) do
								FactoryGirl.generate :metasploit_framework_module_path_gem
							end

							context 'without name_was blank' do
								let(:name_was) do
									FactoryGirl.generate :metasploit_framework_module_path_name
								end

								it 'should delete name_was from path_set.path_by_name_by_gem' do
									expect {
										save!
									}.to change {
										path_by_name = path_set.path_by_name_by_gem[gem_was]
										path_by_name.has_key? name_was
									}.to(false)
								end

								it 'should add path to path_set.path_by_name_by_gem' do
									save!

									path_by_name = path_set.path_by_name_by_gem[gem]
									path_by_name[name].should == path
								end
							end
						end
					end
				end

				context 'without gem changed' do
					let(:gem) do
						gem_was
					end

					context 'with name changed' do
						let(:name) do
							FactoryGirl.generate :metasploit_framework_module_path_name
						end

						context 'without gem_was blank' do
							let(:gem_was) do
								FactoryGirl.generate :metasploit_framework_module_path_gem
							end

							context 'without name_was blank' do
								let(:name_was) do
									FactoryGirl.generate :metasploit_framework_module_path_name
								end

								it 'should delete name_was from path_set.path_by_name_by_gem' do
									path_by_name = path_set.path_by_name_by_gem[gem_was]

									expect {
										save!
									}.to change {
										path_by_name.has_key? name_was
									}.to(false)
								end

								it 'should add path to path_set.path_by_name_by_gem' do
									save!

									path_by_name = path_set.path_by_name_by_gem[gem]
									path_by_name[name].should == path
								end
							end
						end
					end

					context 'without name changed' do
						let(:name) do
							name_was
						end

						context 'with gem_was blank' do
							let(:gem_was) do
								nil
							end

							context 'with name_was blank' do
								let(:name_was) do
									nil
								end

								it 'should not look up path_by_name in path_set.path_by_name_by_gem' do
									path_set.path_by_name_by_gem.should_not_receive(:[]).with(gem_was)

									save!
								end

								it 'should not add path to path_set.path_by_name_by_gem' do
									save!

									path_by_name = path_set.path_by_name_by_gem[gem]
									path_by_name.should_not have_key(name)
								end
							end
						end

						context 'without gem_was blank' do
							let(:gem_was) do
								FactoryGirl.generate :metasploit_framework_module_path_gem
							end

							context 'without name_was blank' do
								let(:name_was) do
									FactoryGirl.generate :metasploit_framework_module_path_name
								end

								it 'should not delete name_was from path_set.path_by_name_by_gem' do
									expect {
										save!
									}.to_not change {
										path_by_name = path_set.path_by_name_by_gem[gem_was]
										path_by_name.has_key? name_was
									}
								end

								it 'should add path to path_set.path_by_name_by_gem' do
									save!

									path_by_name = path_set.path_by_name_by_gem[gem]
									path_by_name[name].should == path
								end
							end
						end
					end
				end
			end

			context 'real_path' do
				context 'with real_path_changed?' do
					let(:real_path) do
						FactoryGirl.generate :metasploit_framework_module_path_real_path
					end

					let(:real_path_was) do
						nil
					end

					before(:each) do
						path.real_path = real_path_was

						# clear change from above to simulate path already being saved once
						path.instance_variable_get(:@changed_attributes).clear

						path.real_path = real_path
					end

					context 'with real_path_was nil' do
						it 'should not delete real_path_was from path_set.path_by_real_path' do
							path_set.path_by_real_path.should_not_receive(:delete)

							save!
						end
					end

					context 'without real_path_was nil' do
						let(:real_path_was) do
							FactoryGirl.generate :metasploit_framework_module_path_real_path
						end

						before(:each) do
							# add entry for its deletion can be tested
							path_set.path_by_real_path[real_path_was] = path
						end

						it 'should delete real_path_was from path_set.path_by_real_path' do
							expect {
								save!
							}.to change {
								path_set.path_by_real_path.has_key?(real_path_was)
							}.to(false)
						end
					end

					it 'should add real_path to path_set.path_by_real_path' do
						save!

						path_set.path_by_real_path[real_path].should == path
					end
				end

				context 'without real_path_changed?' do
					before(:each) do
						path.instance_variable_get(:@changed_attributes).clear
					end

					it 'should not change path_set.path_by_real_path' do
						expect {
							save!
						}.to_not change(path_set, :path_by_real_path)
					end
				end
			end
		end

		context 'without valid' do
			let(:path) do
				described_class.new
			end

			it 'should raise Metasploit::Framework::ModelInvalid' do
				expect {
					save!
				}.to raise_error { |error|
					error.should be_a Metasploit::Framework::ModelInvalid
					error.model.should == path
				}
			end
		end
	end

	context '#update_module_ancestor_real_paths' do
		let(:path) do
			FactoryGirl.build(:metasploit_framework_module_path)
		end

		let(:new_real_path) do
			FactoryGirl.generate :metasploit_framework_module_path_real_path
		end

		context 'with #module_ancestors', :pending => 'https://www.pivotaltracker.com/story/show/56004816' do
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