shared_examples_for 'Msf::DBManager#update_all_module_details refresh' do

	it 'should destroy Mdm::Module::Detail' do
		expect {
			update_all_module_details
		}.to change(Mdm::Module::Detail, :count).by(-1)
	end

	context 'with cached module in Msf::ModuleSet' do
		let(:module_set) do
			framework.exploits
		end

		before(:each) do
			module_set[module_detail.refname] = Msf::SymbolicModule

			framework.modules.send(:module_info_by_path)[module_detail.file] = {
					:parent_path => Metasploit::Framework.root.join('modules').to_path,
					:reference_name => module_detail.refname,
					:type => type
			}
		end

		it 'should create instance of module corresponding to Mdm::Module::Detail' do
			module_set.should_receive(:create).with(module_detail.refname)

			update_all_module_details
		end

		it 'should call update_module_details to create a new Mdm::Module::Detail from the module instance returned by create' do
			db_manager.should_receive(:update_module_details) do |module_instance|
				module_instance.should be_a Msf::Module
				module_instance.type.should == module_detail.mtype
				module_instance.refname.should == module_detail.refname
			end

			update_all_module_details
		end

		context 'with exception raised by #update_module_details' do
			before(:each) do
				db_manager.stub(:update_module_details).and_raise(Exception)
			end

			it 'should log error' do
				db_manager.should_receive(:elog)

				update_all_module_details
			end
		end
	end

	context 'without cached module in Msf::ModuleSet' do
		it 'should not call update_module_details' do
			db_manager.should_not_receive(:update_module_details)

			update_all_module_details
		end
	end
end