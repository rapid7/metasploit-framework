RSpec.describe Mdm::Ref, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    # shoulda matchers don't have support for :primary_key option, so need to
    # test this association manually
    context 'module_refs' do
      context 'with Mdm::Module::Refs' do
        context 'with same name' do
          let(:name) do
            FactoryBot.generate :mdm_ref_name
          end

          let!(:module_ref) do
            FactoryBot.create(:mdm_module_ref, :name => name)
          end

          let!(:ref) do
            FactoryBot.create(:mdm_ref, :name => name)
          end

          it 'should have module_refs in assocation' do
            expect(ref.module_refs).to match_array([module_ref])
          end
        end
      end
    end

    # @todo https://www.pivotaltracker.com/story/show/48915453
    it { is_expected.to have_many(:vulns_refs).class_name('Mdm::VulnRef') }
    it { is_expected.to have_many(:vulns).class_name('Mdm::Vuln').through(:vulns_refs) }
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:name).of_type(:string) }
      it { is_expected.to have_db_column(:ref_id).of_type(:integer) }

      context 'timestamps' do
        it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
        it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
      end
    end

    context 'indices' do
      it { is_expected.to have_db_index(:name) }
    end
  end

  context 'factories' do
    context 'mdm_ref' do
      subject(:mdm_ref) do
        FactoryBot.build :mdm_ref
      end

      it { is_expected.to be_valid }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      mdm_ref = FactoryBot.create(:mdm_ref)
      expect {
        mdm_ref.destroy
      }.to_not raise_error
      expect {
        mdm_ref.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end
end
