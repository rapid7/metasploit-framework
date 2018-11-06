RSpec.describe Mdm::TaskSession, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      task_session = FactoryBot.build(:mdm_task_session)
      expect(task_session).to be_valid
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:task_id).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:session_id).of_type(:integer).with_options(:null => false) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      task_session = FactoryBot.create(:mdm_task_session)
      expect {
        task_session.destroy
      }.to_not raise_error
      expect {
        task_session.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context "validations" do
    it "should not allow duplicate associations" do
      task = FactoryBot.build(:mdm_task)
      session = FactoryBot.build(:mdm_session)
      FactoryBot.create(:mdm_task_session, :task => task, :session => session)
      task_session2 = FactoryBot.build(:mdm_task_session, :task => task, :session => session)
      expect(task_session2).not_to be_valid
    end
  end

end
