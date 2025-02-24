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
      module_set[module_detail.refname] = nil

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

    it 'should create a new Mdm::Module::Detail entry' do
      update_all_module_details

      aggregate_failures do
        expect(Mdm::Module::Detail.count).to eq 1
        db_module_detail = Mdm::Module::Detail.first
        expect(db_module_detail.mtype).to eq(module_detail.mtype)
        expect(db_module_detail.refname).to eq(module_detail.refname)
      end
    end

    context 'with exception raised by #insert_all' do
      before(:example) do
        expect(db_manager).to receive(:module_to_details_hash).and_raise(Exception)
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
