RSpec.describe Mdm::Client, type: :model do

  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      client = FactoryBot.create(:mdm_client, :ua_string => 'user-agent')
      expect {
        client.destroy
      }.to_not raise_error
      expect {
        client.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'factory' do
    it 'should be valid' do
      client = FactoryBot.build(:mdm_client)
      expect(client).to be_valid
    end
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:host_id).of_type(:integer)}
      it { is_expected.to have_db_column(:ua_string).of_type(:string).with_options(:null => false) }
      it { is_expected.to have_db_column(:ua_name).of_type(:string) }
      it { is_expected.to have_db_column(:ua_ver).of_type(:string) }
    end

    context 'timestamps' do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
    end

  end

end
