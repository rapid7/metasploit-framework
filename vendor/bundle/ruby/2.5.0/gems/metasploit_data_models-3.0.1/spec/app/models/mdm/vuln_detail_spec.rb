RSpec.describe Mdm::VulnDetail, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'association' do
    it { is_expected.to belong_to(:vuln).class_name('Mdm::Vuln') }
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:nx_published).of_type(:datetime) }
      it { is_expected.to have_db_column(:nx_added).of_type(:datetime) }
      it { is_expected.to have_db_column(:nx_modified).of_type(:datetime) }
      it { is_expected.to have_db_column(:nx_vulnerable_since).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:vuln_id).of_type(:integer)}
      it { is_expected.to have_db_column(:cvss_score).of_type(:float) }
      it { is_expected.to have_db_column(:cvss_vector).of_type(:string) }
      it { is_expected.to have_db_column(:title).of_type(:string) }
      it { is_expected.to have_db_column(:description).of_type(:text) }
      it { is_expected.to have_db_column(:solution).of_type(:text) }
      it { is_expected.to have_db_column(:proof).of_type(:binary) }
      it { is_expected.to have_db_column(:nx_console_id).of_type(:integer) }
      it { is_expected.to have_db_column(:nx_device_id).of_type(:integer) }
      it { is_expected.to have_db_column(:nx_severity).of_type(:float) }
      it { is_expected.to have_db_column(:nx_pci_severity).of_type(:float) }
      it { is_expected.to have_db_column(:nx_tags).of_type(:text) }
      it { is_expected.to have_db_column(:nx_vuln_status).of_type(:text) }
      it { is_expected.to have_db_column(:nx_proof_key).of_type(:text) }
      it { is_expected.to have_db_column(:src).of_type(:string) }
      it { is_expected.to have_db_column(:nx_scan_id).of_type(:integer) }
      it { is_expected.to have_db_column(:nx_pci_compliance_status).of_type(:string) }
    end
  end

  context 'validations' do
    it 'should require a vuln_id' do
      orphan_detail = FactoryBot.build(:mdm_vuln_detail, :vuln => nil)
      expect(orphan_detail).not_to be_valid
      expect(orphan_detail.errors[:vuln_id]).to include("can't be blank")
    end
  end

  context 'factory' do
    it 'should be valid' do
      vuln_detail = FactoryBot.build(:mdm_vuln_detail)
      expect(vuln_detail).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      vuln_detail = FactoryBot.create(:mdm_vuln_detail)
      expect {
        vuln_detail.destroy
      }.to_not raise_error
      expect {
        vuln_detail.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

end
