RSpec.describe Mdm::Module::Ref, type: :model do

  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:detail).class_name('Mdm::Module::Detail') }

    # shoulda matchers don't have support for :primary_key option, so need
    # to test this association manually
    context 'refs' do
      context 'with Mdm::Refs' do
        context 'with same name' do
          let(:name) do
            FactoryBot.generate :mdm_module_ref_name
          end

          let!(:module_ref) do
            FactoryBot.create(:mdm_module_ref, :name => name)
          end

          let!(:ref) do
            FactoryBot.create(:mdm_ref, :name => name)
          end

          it 'should have refs in association' do
            expect(module_ref.refs).to match_array([ref])
          end
        end
      end
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:detail_id).of_type(:integer) }
      it { is_expected.to have_db_column(:name) }
    end

    context 'indices' do
      it { is_expected.to have_db_column(:detail_id) }
    end
  end

  context 'factories' do
    context 'mdm_module_ref' do
      subject(:mdm_module_ref) do
        FactoryBot.build :mdm_module_ref
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of(:detail) }
    it { is_expected.to validate_presence_of(:name) }
  end
end
