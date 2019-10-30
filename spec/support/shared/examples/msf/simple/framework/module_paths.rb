RSpec.shared_examples_for 'Msf::Simple::Framework::ModulePaths' do
  it { is_expected.to be_a Msf::Simple::Framework::ModulePaths }

  context '#init_module_paths' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    def init_module_paths
      framework.init_module_paths(options)
    end

    let(:module_directory) do
      Rails.application.root.join('modules').expand_path.to_path
    end

    let(:user_module_directory) do
      nil
    end

    let(:options) do
      {}
    end

    before(:example) do
      # create the framework first so that it's initialization's call
      # to init_module_paths doesn't get captured.
      framework

      allow(Msf::Config).to receive(:user_module_directory).and_return(user_module_directory)
    end

    it 'should refresh module cache from database' do
      expect(framework.modules).to receive(:refresh_cache_from_database)

      init_module_paths
    end

    it "adds Rails.application.paths['modules'] to module paths" do
      expect(framework.modules).to receive(:add_module_path).with(module_directory, options)

      init_module_paths
    end

    context 'Msf::Config' do
      before(:example) do
        allow(Rails.application.paths).to receive(:[]).with('modules').and_return(nil)
      end

      context 'user_module_directory' do
        context 'without nil' do
          let(:user_module_directory) do
            'user/modules'
          end

          it 'should add Msf::Config.user_module_directory to module paths' do
            expect(framework.modules).to receive(:add_module_path).with(
                user_module_directory,
                options
            )

            init_module_paths
          end
        end
      end
    end

    context 'datastore' do
      before(:example) do
        allow(Rails.application.paths).to receive(:[]).with('modules').and_return(nil)
      end

      context 'MsfModulePaths' do
        let(:module_paths) do
          module_paths = []

          1.upto(2) do |i|
            module_paths << "msf/#{i}/modules"
          end

          module_paths
        end

        before(:example) do
          msf_module_paths = module_paths.join(';')
          framework.datastore['MsfModulePaths'] = msf_module_paths
        end

        it 'should add each module path' do
          module_paths.each do |module_path|
            expect(framework.modules).to receive(:add_module_path).with(module_path, options)
          end

          init_module_paths
        end
      end
    end
  end
end
