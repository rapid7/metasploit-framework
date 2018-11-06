RSpec.describe Metasploit::Credential::Origin::CrackedPassword, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:cores).class_name('Metasploit::Credential::Core').dependent(:destroy) }
    it { is_expected.to belong_to(:originating_core).class_name('Metasploit::Credential::Core') }
  end

  context 'database' do
    context 'columns' do
      it_should_behave_like 'timestamp database columns'

      context 'foreign keys' do
        it { is_expected.to have_db_column(:metasploit_credential_core_id).of_type(:integer).with_options(null: false) }
      end
    end

    context 'indices' do
      context 'foreign keys' do
        it { is_expected.to have_db_index(:metasploit_credential_core_id) }
      end
    end
  end

end