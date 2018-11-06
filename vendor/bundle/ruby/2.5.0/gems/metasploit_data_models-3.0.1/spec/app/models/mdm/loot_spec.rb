RSpec.describe Mdm::Loot, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:workspace).class_name('Mdm::Workspace') }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:module_run).class_name('MetasploitDataModels::ModuleRun') }
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:workspace_id).of_type(:integer).with_options(:null => false, :default =>1) }
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:service_id).of_type(:integer) }
      it { is_expected.to have_db_column(:ltype).of_type(:string) }
      it { is_expected.to have_db_column(:path).of_type(:string) }
      it { is_expected.to have_db_column(:data).of_type(:text) }
      it { is_expected.to have_db_column(:content_type).of_type(:string) }
      it { is_expected.to have_db_column(:name).of_type(:text) }
      it { is_expected.to have_db_column(:info).of_type(:text) }
    end
  end

  context 'factory' do
    it 'should be valid' do
      loot = FactoryBot.build(:mdm_loot)
      expect(loot).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      loot = FactoryBot.create(:mdm_loot)
      expect {
        loot.destroy
      }.to_not raise_error
      expect {
        loot.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'scopes' do
    context 'search' do
      it 'should match on ltype' do
        myloot = FactoryBot.create(:mdm_loot, :ltype => 'find.this.ltype')
        expect(Mdm::Loot.search('find.this.ltype')).to include(myloot)
      end

      it 'should match on name' do
        myloot = FactoryBot.create(:mdm_loot, :name => 'Find This')
        expect(Mdm::Loot.search('Find This')).to include(myloot)
      end

      it 'should match on info' do
        myloot = FactoryBot.create(:mdm_loot, :info => 'Find This')
        expect(Mdm::Loot.search('Find This')).to include(myloot)
      end

      it 'should match on hostname' do
        myloot = FactoryBot.create(:mdm_loot, :info => 'Find This')
        host_name = myloot.host.name
        expect(Mdm::Loot.search(host_name)).to include(myloot)
      end
    end
  end

  context 'callbacks' do
    context 'before_destroy' do
      it 'should call #delete_file' do
        myloot =  FactoryBot.create(:mdm_loot)
        expect(myloot).to receive(:delete_file)
        myloot.destroy
      end
    end
  end
end
