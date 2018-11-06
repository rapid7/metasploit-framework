RSpec.describe Metasploit::Credential::Public, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'database' do
    context 'columns' do
      it_should_behave_like 'timestamp database columns'

      it { is_expected.to have_db_column(:username).of_type(:string).with_options(null: false) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:username).unique(true) }
    end
  end

  context 'factories' do
    context 'metasploit_credential_public' do
      subject(:metasploit_credential_public) do
        FactoryBot.build(:metasploit_credential_public)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'search' do
    let(:base_class) {
      described_class
    }

    context 'attributes' do
      it_should_behave_like 'search_attribute',
                            :username,
                            type: :string

      it_should_behave_like 'search_with',
                            Metasploit::Credential::Search::Operator::Type,
                            name: :type,
                            class_names: %w{
                              Metasploit::Credential::BlankUsername
                              Metasploit::Credential::Username
                            }
    end
  end

end
