shared_examples_for 'Msf::ModuleManager::Cache' do
	let(:parent_path) do
		parent_pathname.to_path
	end

	let(:parent_pathname) do
		Metasploit::Framework.root.join('modules')
	end

	let(:reference_name) do
		'windows/smb/ms08_067_netapi'
	end

	let(:type) do
		'exploit'
	end

	let(:path) do
		pathname.to_path
	end

	let(:pathname) do
		parent_pathname.join(
				'exploits',
				"#{reference_name}.rb"
		)
	end

	let(:pathname_modification_time) do
		pathname.mtime
	end

	context '#cache_empty?' do
		subject(:cache_empty?) do
			module_manager.cache_empty?
		end

		before(:each) do
			module_manager.send(:module_info_by_path=, module_info_by_path)
		end

		context 'with empty' do
			let(:module_info_by_path) do
				{}
			end

			it { should be_true }
		end

		context 'without empty' do
			let(:module_info_by_path) do
				{
						'path/to/module' => {}
				}
			end

			it { should be_false }
		end
	end

	context '#cache_in_memory' do
		def cache_in_memory
			module_manager.cache_in_memory(
					class_or_module,
					:path => path,
					:reference_name => reference_name,
					:type => type
			)
		end

		def module_info_by_path
			module_manager.send(:module_info_by_path)
		end

		let(:class_or_module) do
			mock('Class<Msf::Module> or Module', :parent => namespace_module)
		end

		let(:namespace_module) do
			mock('Msf::Modules::Namespace', :parent_path => parent_path)
		end

		context 'with existing :path' do
			it 'should update module_info_by_path' do
				expect {
					cache_in_memory
				}.to change { module_info_by_path }
			end

			context 'module_info_by_path' do
				subject(:module_info_by_path) do
					module_manager.send(:module_info_by_path)
				end

				before(:each) do
					cache_in_memory
				end

				it 'should have entry for path' do
					module_info_by_path[path].should be_a Hash
				end

				context 'value' do
					subject(:value) do
						module_info_by_path[path]
					end

					it 'should have modification time of :path option for :modification_time' do
						value[:modification_time].should == pathname_modification_time
					end

					it 'should have parent path from namespace module for :parent_path' do
						value[:parent_path].should == namespace_module.parent_path
					end

					it 'should use :reference_name option' do
						value[:reference_name].should == reference_name
					end

					it 'should use :type option' do
						value[:type].should == type
					end
				end
			end
		end

		context 'without existing :path' do
			let(:path) do
				'non/existent/path'
			end

			it 'should not raise error' do
				expect {
					cache_in_memory
				}.to_not raise_error
			end

			it 'should not update module_info_by_path' do
				expect {
					cache_in_memory
				}.to_not change { module_info_by_path }
			end
		end
	end

	context '#load_cached_module' do
		subject(:load_cached_module) do
			module_manager.load_cached_module(type, reference_name)
		end

		before(:each) do
			module_manager.send(:module_info_by_path=, module_info_by_path)
		end

		context 'with module info in cache' do
			let(:module_info_by_path) do
				{
						'path/to/module' => {
								:parent_path => parent_path,
								:reference_name => reference_name,
								:type => type
						}
				}
			end

			it 'should enumerate loaders until if it find the one where loadable?(parent_path) is true' do
				module_manager.send(:loaders).each do |loader|
					loader.should_receive(:loadable?).with(parent_path).and_call_original
				end

				load_cached_module
			end

			it 'should force load using #load_module on the loader' do
				Msf::Modules::Loader::Directory.any_instance.should_receive(
						:load_module
				).with(
						parent_path,
						type,
						reference_name,
						:force => true
				).and_call_original

				load_cached_module
			end

			context 'return from load_module' do
				before(:each) do
					module_manager.send(:loaders).each do |loader|
						loader.stub(:load_module => module_loaded)
					end
				end

				context 'with false' do
					let(:module_loaded) do
						false
					end

					it { should be_false }
				end

				context 'with true' do
					let(:module_loaded) do
						true
					end

					it { should be_true }
				end
			end
		end

		context 'without module info in cache' do
			let(:module_info_by_path) do
				{}
			end

			it { should be_false }
		end
	end

	context '#refresh_cache_from_module_files' do
		before(:each) do
			module_manager.stub(:framework_migrated? => framework_migrated?)
		end

		context 'with framework migrated' do
			let(:framework_migrated?) do
				true
			end

			context 'with module argument' do
				def refresh_cache_from_module_files
					module_manager.refresh_cache_from_module_files(module_class_or_instance)
				end

				let(:module_class_or_instance) do
					Class.new(Msf::Module)
				end

				it 'should update database and then update in-memory cache from the database for the given module_class_or_instance' do
					framework.db.should_receive(:update_module_details).with(module_class_or_instance).ordered
					module_manager.should_receive(:refresh_cache_from_database).ordered

					refresh_cache_from_module_files
				end
			end

			context 'without module argument' do
				def refresh_cache_from_module_files
					module_manager.refresh_cache_from_module_files
				end

				it 'should update database and then update in-memory cache from the database for all modules' do
					framework.db.should_receive(:update_all_module_details).ordered
					module_manager.should_receive(:refresh_cache_from_database)

					refresh_cache_from_module_files
				end
			end
		end

		context 'without framework migrated' do
			def refresh_cache_from_module_files
				module_manager.refresh_cache_from_module_files
			end

			let(:framework_migrated?) do
				false
			end

			it 'should not call Msf::DBManager#update_module_details' do
				framework.db.should_not_receive(:update_module_details)

				refresh_cache_from_module_files
			end

			it 'should not call Msf::DBManager#update_all_module_details' do
				framework.db.should_not_receive(:update_all_module_details)

				refresh_cache_from_module_files
			end

			it 'should not call #refresh_cache_from_database' do
				module_manager.should_not_receive(:refresh_cache_from_database)

				refresh_cache_from_module_files
			end
		end
	end

	context '#refresh_cache_from_database' do
		def refresh_cache_from_database
			module_manager.refresh_cache_from_database
		end

		it 'should call #module_info_by_path_from_database!' do
		  module_manager.should_receive(:module_info_by_path_from_database!)

			refresh_cache_from_database
		end
	end

	context '#framework_migrated?' do
		subject(:framework_migrated?) do
			module_manager.send(:framework_migrated?)
		end

		context 'with framework database' do
			before(:each) do
				framework.db.stub(:migrated => migrated)
			end

			context 'with migrated' do
				let(:migrated) do
					true
				end

				it { should be_true }
			end

			context 'without migrated' do
				let(:migrated) do
					false
				end

				it { should be_false }
			end
		end

		context 'without framework database' do
			before(:each) do
				framework.stub(:db => nil)
			end

			it { should be_false }
		end
	end

	context '#module_info_by_path' do
		it { should respond_to(:module_info_by_path) }
	end

	context '#module_info_by_path=' do
		it { should respond_to(:module_info_by_path=) }
	end

	context '#module_info_by_path_from_database!' do
		def module_info_by_path
			module_manager.send(:module_info_by_path)
		end

		def module_info_by_path_from_database!
			module_manager.send(:module_info_by_path_from_database!)
		end

		before(:each) do
			module_manager.stub(:framework_migrated? => framework_migrated?)
		end

		context 'with framework migrated' do
			include_context 'DatabaseCleaner'

			let(:framework_migrated?) do
				true
			end

			before(:each) do
				configurations = Metasploit::Framework::Database.configurations
				spec = configurations[Metasploit::Framework.env]

				# Need to connect or ActiveRecord::Base.connection_pool will raise an
				# error.
				framework.db.connect(spec)
			end

			it 'should call ActiveRecord::Base.connection_pool.with_connection' do
				# 1st is from with_established_connection
				# 2nd is from module_info_by_path_from_database!
				ActiveRecord::Base.connection_pool.should_receive(:with_connection).at_least(2).times

				module_info_by_path_from_database!
			end

      it 'should use ActiveRecord::Batches#find_each to enumerate Mdm::Module::Details in batches' do
	      Mdm::Module::Detail.should_receive(:find_each)

	      module_info_by_path_from_database!
      end

			context 'with database cache' do
				#
				# Let!s (let + before(:each))
				#

				let!(:mdm_module_detail) do
					FactoryGirl.create(:mdm_module_detail,
					                   :file => path,
					                   :mtype => type,
					                   :mtime => pathname.mtime,
					                   :refname => reference_name
					)
				end

				it 'should create cache entry for path' do
					module_info_by_path_from_database!

					module_info_by_path.should have_key(path)
				end

				it 'should use Msf::Modules::Loader::Base.typed_path to derive parent_path' do
					Msf::Modules::Loader::Base.should_receive(:typed_path).with(type, reference_name).and_call_original

					module_info_by_path_from_database!
				end

				context 'cache entry' do
					subject(:cache_entry) do
						module_info_by_path[path]
					end

					before(:each) do
						module_info_by_path_from_database!
					end

					its([:modification_time]) { should be_within(1.second).of(pathname_modification_time) }
					its([:parent_path]) { should == parent_path }
					its([:reference_name]) { should == reference_name }
					its([:type]) { should == type }
				end

				context 'typed module set' do
					let(:typed_module_set) do
						module_manager.module_set(type)
					end

					context 'with reference_name' do
						before(:each) do
							typed_module_set[reference_name] = mock('Msf::Module')
						end

						it 'should not change reference_name value' do
							expect {
								module_info_by_path_from_database!
							}.to_not change {
								typed_module_set[reference_name]
							}
						end
					end

					context 'without reference_name' do
						it 'should set reference_name value to Msf::SymbolicModule' do
							module_info_by_path_from_database!

							# have to use fetch because [] will trigger de-symbolization and
							# instantiation.
							typed_module_set.fetch(reference_name).should == Msf::SymbolicModule
						end
					end
				end
			end
		end

		context 'without framework migrated' do
			let(:framework_migrated?) do
				false
			end

			it { should_not query_the_database.when_calling(:module_info_by_path_from_database!) }

			it 'should reset #module_info_by_path' do
				# pre-fill module_info_by_path so change can be detected
				module_manager.send(:module_info_by_path=, mock('In-memory Cache'))

				module_info_by_path_from_database!

				module_info_by_path.should be_empty
			end
		end
	end
end