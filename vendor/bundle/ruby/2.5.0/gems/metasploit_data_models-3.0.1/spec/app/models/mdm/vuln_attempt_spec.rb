RSpec.describe Mdm::VulnAttempt, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'association' do
    it { is_expected.to belong_to(:vuln).class_name('Mdm::Vuln') }
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:attempted_at).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:vuln_id).of_type(:integer) }
      it { is_expected.to have_db_column(:exploited).of_type(:boolean) }
      it { is_expected.to have_db_column(:fail_reason).of_type(:string) }
      it { is_expected.to have_db_column(:username).of_type(:string) }
      it { is_expected.to have_db_column(:module).of_type(:text) }
      it { is_expected.to have_db_column(:session_id).of_type(:integer) }
      it { is_expected.to have_db_column(:loot_id).of_type(:integer) }
      it { is_expected.to have_db_column(:fail_detail).of_type(:text) }
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
      vuln_attempt = FactoryBot.build(:mdm_vuln_attempt)
      expect(vuln_attempt).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      vuln_attempt = FactoryBot.create(:mdm_vuln_attempt)
      expect {
        vuln_attempt.destroy
      }.to_not raise_error
      expect {
        vuln_attempt.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

end
