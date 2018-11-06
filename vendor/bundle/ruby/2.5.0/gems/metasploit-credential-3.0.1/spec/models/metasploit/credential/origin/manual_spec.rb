RSpec.describe Metasploit::Credential::Origin::Manual, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:cores).class_name('Metasploit::Credential::Core').dependent(:destroy) }
    it { is_expected.to belong_to(:user).class_name('Mdm::User') }
  end

  context 'database' do
    context 'columns' do
      context 'foreign keys' do
        it { is_expected.to have_db_column(:user_id).of_type(:integer).with_options(null: false) }
      end

      it_should_behave_like 'timestamp database columns'
    end

    context 'indices' do
      context 'foreign keys' do
        it { is_expected.to have_db_index(:user_id) }
      end
    end
  end

  context 'factories' do
    context 'metasploit_credential_origin_manual' do
      subject(:metasploit_credential_origin_manual) do
        FactoryBot.build(:metasploit_credential_origin_manual)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of :user }
  end
end
