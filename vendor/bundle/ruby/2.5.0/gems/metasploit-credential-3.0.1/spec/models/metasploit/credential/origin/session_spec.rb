RSpec.describe Metasploit::Credential::Origin::Session, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:cores).class_name('Metasploit::Credential::Core').dependent(:destroy) }
    it { is_expected.to belong_to(:session).class_name('Mdm::Session') }
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:post_reference_name).of_type(:text).with_options(null: false) }

      it_should_behave_like 'timestamp database columns'

      context 'foreign keys' do
        it { is_expected.to have_db_column(:session_id).of_type(:integer).with_options(null: false) }
      end
    end

    context 'columns' do
      it { is_expected.to have_db_index([:session_id, :post_reference_name]).unique(true) }
    end
  end

  context 'factories' do
    context 'metasploit_credential_origin_session' do


      subject(:metasploit_credential_origin_session) do
        FactoryBot.build(:metasploit_credential_origin_session)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    context 'post_reference_name' do


      before(:example) do
        FactoryBot.create(:metasploit_credential_origin_session)
      end

      it { is_expected.to validate_presence_of :post_reference_name }
      it { is_expected.to validate_uniqueness_of(:post_reference_name).scoped_to(:session_id) }
    end

    it { is_expected.to validate_presence_of :session }
  end
end
