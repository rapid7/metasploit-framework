shared_examples_for 'Msf::Simple::Framework::ModulePaths' do
	it { should be_a Msf::Simple::Framework::ModulePaths }

	context '#init_module_paths' do
		def init_module_paths
			framework.init_module_paths
		end

		let(:module_directory) do
			nil
		end

		let(:user_module_directory) do
			nil
		end

		before(:each) do
			# create the framework first so that it's initialization's call
			# to init_module_paths doesn't get captured.
			framework

			Msf::Config.stub(:module_directory => module_directory)
			Msf::Config.stub(:user_module_directory => user_module_directory)
		end

		context 'Msf::Config' do
			context 'module_directory' do
				context 'without nil' do
					let(:module_directory) do
						'modules'
					end

          it "should add Msf::Config.module_directory to module paths with gem: 'metasploit-framework' and name: 'modules'" do
            framework.modules.should_receive(:add_path).with(
                module_directory,
                gem: 'metasploit-framework',
                name: 'modules'
            )

            init_module_paths
          end
				end
			end

			context 'user_module_directory' do
				context 'without nil' do
					let(:user_module_directory) do
						'user/modules'
					end

          it "should add Msf::Config.user_module_directory to module paths with gem: 'metasploit-framework' and name: 'user'" do
            framework.modules.should_receive(:add_path).with(
                user_module_directory,
                gem: 'metasploit-framework',
                name: 'user'
            )

            init_module_paths
          end
				end
			end
		end

		context 'datastore' do
			context 'MsfModulePaths' do
				let(:module_paths) do
					module_paths = []

					1.upto(2) do |i|
						module_paths << "msf/#{i}/modules"
					end

					module_paths
				end

				before(:each) do
					msf_module_paths = module_paths.join(';')
					framework.datastore['MsfModulePaths'] = msf_module_paths
				end

				it 'should add each module path with gem or name' do
					module_paths.each do |module_path|
						framework.modules.should_receive(:add_path).with(module_path)
					end

					init_module_paths
				end
			end
		end
	end
end