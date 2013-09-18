shared_examples_for 'Msf::ModuleManager::Loading' do
	context '#on_module_load' do
		def on_module_load
			module_manager.on_module_load(klass, type, reference_name, options)
		end

		let(:klass) do
			Class.new(Msf::Auxiliary)
		end

		let(:module_set) do
			module_manager.module_set_by_module_type[type]
		end

		let(:namespace_module) do
			mock('Namespace Module', :parent_path => parent_path)
		end

		let(:options) do
			{
					'files' => [
							path
					],
					'paths' => [
							reference_name
					],
					'type' => type
			}
		end

		let(:parent_path) do
			Metasploit::Framework.root.join('modules')
		end

		let(:path) do
			type_directory = Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[type]

			File.join(parent_path, type_directory, "#{reference_name}.rb")
		end

		let(:reference_name) do
			'admin/2wire/xslt_password_reset'
		end

		let(:type) do
			klass.type
		end

		before(:each) do
			klass.stub(:parent => namespace_module)
		end

		it "should add module to type's module_set" do
			module_set.should_receive(:add_module).with(
					klass,
					reference_name,
					options
			)

			on_module_load
		end

		it 'should pass class to #auto_subscribe_module' do
			module_manager.should_receive(:auto_subscribe_module).with(klass)

			on_module_load
		end

		it 'should fire on_module_load event with class' do
			framework.events.should_receive(:on_module_load).with(
					reference_name,
					klass
			)

			on_module_load
		end
	end
end