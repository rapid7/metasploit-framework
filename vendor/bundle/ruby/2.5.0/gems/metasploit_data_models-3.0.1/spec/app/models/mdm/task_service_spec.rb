RSpec.describe Mdm::TaskService, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      task_service = FactoryBot.build(:mdm_task_service)
      expect(task_service).to be_valid
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:task_id).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:service_id).of_type(:integer).with_options(:null => false) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      task_service = FactoryBot.create(:mdm_task_service)
      expect {
        task_service.destroy
      }.to_not raise_error
      expect {
        task_service.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context "Associations" do
    it { is_expected.to belong_to(:task).class_name('Mdm::Task') }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
  end

  context "validations" do
    it "should not allow duplicate associations" do
      task = FactoryBot.build(:mdm_task)
      service = FactoryBot.build(:mdm_service)
      FactoryBot.create(:mdm_task_service, :task => task, :service => service)
      task_service2 = FactoryBot.build(:mdm_task_service, :task => task, :service => service)
      expect(task_service2).not_to be_valid
    end
  end
end
