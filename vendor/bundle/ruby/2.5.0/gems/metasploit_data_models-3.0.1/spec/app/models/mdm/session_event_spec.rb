RSpec.describe Mdm::SessionEvent, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:session).class_name('Mdm::Session') }
  end

  context 'factory' do
    it 'should be valid' do
      session_event = FactoryBot.build(:mdm_session_event)
      expect(session_event).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      session_event = FactoryBot.create(:mdm_session_event)
      expect {
        session_event.destroy
      }.to_not raise_error
      expect {
        session_event.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'database' do
    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:session_id).of_type(:integer) }
      it { is_expected.to have_db_column(:etype).of_type(:string) }
      it { is_expected.to have_db_column(:command).of_type(:binary) }
      it { is_expected.to have_db_column(:output).of_type(:binary) }
      it { is_expected.to have_db_column(:remote_path).of_type(:string) }
      it { is_expected.to have_db_column(:local_path).of_type(:string) }
    end
  end

end
