RSpec.describe Mdm::HostDetail, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
  end

  context 'database' do
    it { is_expected.to have_db_column(:host_id).of_type(:integer) }
    it { is_expected.to have_db_column(:nx_console_id).of_type(:integer) }
    it { is_expected.to have_db_column(:nx_device_id).of_type(:integer) }
    it { is_expected.to have_db_column(:src).of_type(:string) }
    it { is_expected.to have_db_column(:nx_site_name).of_type(:string) }
    it { is_expected.to have_db_column(:nx_site_importance).of_type(:string) }
    it { is_expected.to have_db_column(:src).of_type(:string) }
    it { is_expected.to have_db_column(:nx_site_name).of_type(:string) }
    it { is_expected.to have_db_column(:nx_scan_template).of_type(:string) }
    it { is_expected.to have_db_column(:nx_risk_score).of_type(:float) }
  end

  context 'validations' do
    it 'should only be valid with a host_id' do
      orphan_detail = FactoryBot.build(:mdm_host_detail, :host => nil)
      expect(orphan_detail).not_to be_valid
      expect(orphan_detail.errors[:host_id]).to include("can't be blank")
    end
  end

  context 'factory' do
    it 'should be valid' do
      host_detail = FactoryBot.build(:mdm_host_detail)
      expect(host_detail).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      detail = FactoryBot.create(:mdm_host_detail)
      expect{
        detail.destroy
      }.to_not raise_error
      expect {
        detail.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

end
