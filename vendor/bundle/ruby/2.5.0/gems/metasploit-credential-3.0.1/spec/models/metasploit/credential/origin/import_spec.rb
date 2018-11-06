RSpec.describe Metasploit::Credential::Origin::Import, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:cores).class_name('Metasploit::Credential::Core').dependent(:destroy) }
    it { is_expected.to belong_to(:task).class_name('Mdm::Task') }
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:filename).of_type(:text).with_options(null: false) }

      it_should_behave_like 'timestamp database columns'

      context 'foreign keys' do
        it { is_expected.to have_db_column(:task_id).of_type(:integer) }
      end
    end

    context 'indices' do
      context 'foreign keys' do
        it { is_expected.to have_db_index(:task_id) }
      end
    end
  end

  context 'factories' do


    subject(:metasploit_credential_origin_import) do
      FactoryBot.build(:metasploit_credential_origin_import)
    end

    it { is_expected.to be_valid }
  end
end
