RSpec.describe Mdm::VulnRef, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factories' do
    context 'mdm_vuln_ref' do
      subject(:mdm_vuln_ref) do
        FactoryBot.build(:mdm_vuln_ref)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:id).of_type(:integer) }
      it { is_expected.to have_db_column(:ref_id).of_type(:integer) }
      it { is_expected.to have_db_column(:vuln_id).of_type(:integer) }
    end
  end

  context 'associations' do
    it { is_expected.to belong_to(:vuln).class_name('Mdm::Vuln') }
    it { is_expected.to belong_to(:ref).class_name('Mdm::Ref') }
  end

  context 'factory' do
    it 'should be valid' do
      vuln_ref = FactoryBot.build(:mdm_vuln_ref)
      expect(vuln_ref).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      vuln_ref = FactoryBot.create(:mdm_vuln_ref)
      expect {
        vuln_ref.destroy
      }.to_not raise_error
      expect {
        vuln_ref.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end
  
end
