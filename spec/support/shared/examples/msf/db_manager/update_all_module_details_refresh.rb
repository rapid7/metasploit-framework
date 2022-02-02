RSpec.shared_examples_for 'Msf::DBManager#update_all_module_details refresh' do

  it 'should destroy Mdm::Module::Detail' do
    expect {
      update_all_module_details
    }.to change(Mdm::Module::Detail, :count).by(-1)
  end

  context 'with cached module in Msf::ModuleSet' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    let(:module_set) do
      framework.exploits
    end

    before(:example) do
      module_set[module_detail.refname] = Msf::SymbolicModule

      framework.modules.send(:module_info_by_path)[module_detail.file] = {
          :parent_path => Metasploit::Framework.root.join('modules').to_path,
          :reference_name => module_detail.refname,
          :type => type
      }
    end

    it 'should create instance of module corresponding to Mdm::Module::Detail' do
      expect(module_set).to receive(:create).with(module_detail.refname)

      update_all_module_details
    end

    it 'should call update_module_details to create a new Mdm::Module::Detail from the module instance returned by create' do
      expect(db_manager).to receive(:update_module_details) do |module_instance|
        expect(module_instance).to be_a Msf::Module
        expect(module_instance.type).to eq module_detail.mtype
        expect(module_instance.refname).to eq module_detail.refname
      end

      update_all_module_details
    end

    context 'with exception raised by #update_module_details' do
      before(:example) do
        expect(db_manager).to receive(:update_module_details).and_raise(Exception)
      end

      it 'should log error' do
        expect(db_manager).to receive(:elog)

        update_all_module_details
      end
    end
  end

  context 'without cached module in Msf::ModuleSet' do
    it 'should not call update_module_details' do
      expect(db_manager).not_to receive(:update_module_details)

      update_all_module_details
    end
  end
end
