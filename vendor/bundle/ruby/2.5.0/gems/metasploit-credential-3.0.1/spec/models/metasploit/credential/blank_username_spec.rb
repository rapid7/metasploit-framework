RSpec.describe Metasploit::Credential::BlankUsername, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'database' do
    context 'columns' do
      it_should_behave_like 'timestamp database columns'

      it { is_expected.to have_db_column(:username).of_type(:string).with_options(null: false) }
      it { is_expected.to have_db_column(:type).of_type(:string).with_options(null: false) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:username).unique(true) }
    end
  end
end
