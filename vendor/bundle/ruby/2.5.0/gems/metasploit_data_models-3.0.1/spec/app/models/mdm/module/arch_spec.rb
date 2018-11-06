RSpec.describe Mdm::Module::Arch, type: :model do

  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:detail).class_name('Mdm::Module::Detail') }
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:detail_id).of_type(:integer) }
      it { is_expected.to have_db_column(:name).of_type(:text) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:detail_id) }
    end
  end

  context 'factories' do
    context 'mdm_module_arch' do
      subject(:mdm_module_arch) do
        FactoryBot.build(:mdm_module_arch)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of(:detail) }
    it { is_expected.to validate_presence_of(:name) }
  end
end
