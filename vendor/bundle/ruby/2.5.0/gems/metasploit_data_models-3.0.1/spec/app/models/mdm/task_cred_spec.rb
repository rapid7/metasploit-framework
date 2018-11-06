RSpec.describe Mdm::TaskCred, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      task_cred = FactoryBot.build(:mdm_task_cred)
      expect(task_cred).to be_valid
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:task_id).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:cred_id).of_type(:integer).with_options(:null => false) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      task_cred = FactoryBot.create(:mdm_task_cred)
      expect {
        task_cred.destroy
      }.to_not raise_error
      expect {
        task_cred.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context "Associations" do
    it { is_expected.to belong_to(:task).class_name('Mdm::Task') }
    it { is_expected.to belong_to(:cred).class_name('Mdm::Cred') }
  end

  context "validations" do
    it "should not allow duplicate associations" do
      task = FactoryBot.build(:mdm_task)
      cred = FactoryBot.build(:mdm_cred)
      FactoryBot.create(:mdm_task_cred, :task => task, :cred => cred)
      task_cred2 = FactoryBot.build(:mdm_task_cred, :task => task, :cred => cred)
      expect(task_cred2).not_to be_valid
    end
  end

end
