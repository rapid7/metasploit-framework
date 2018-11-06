RSpec.describe Mdm::Route, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:session).class_name('Mdm::Session') }
  end

  context 'factory' do
    it 'should be valid' do
      route = FactoryBot.build(:mdm_route)
      expect(route).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      route = FactoryBot.create(:mdm_route)
      expect {
        route.destroy
      }.to_not raise_error
      expect {
        route.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:session_id).of_type(:integer) }
      it { is_expected.to have_db_column(:subnet).of_type(:string) }
      it { is_expected.to have_db_column(:netmask).of_type(:string) }
    end
  end

end
