RSpec.describe Mdm::Event, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:workspace).class_name('Mdm::Workspace') }
  end

  context 'database' do
    context 'timestamps' do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:workspace_id).of_type(:integer) }
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:name).of_type(:string) }
      it { is_expected.to have_db_column(:critical).of_type(:boolean) }
      it { is_expected.to have_db_column(:seen).of_type(:boolean) }
      it { is_expected.to have_db_column(:username).of_type(:string) }
      it { is_expected.to have_db_column(:info).of_type(:text) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object and all dependent objects' do
      event = FactoryBot.create(:mdm_event)
      expect {
        event.destroy
      }.to_not raise_error
      expect {
        event.reload
      }.to raise_error(ActiveRecord::RecordNotFound)

    end
  end

  context 'scopes' do
    context 'flagged' do
      let(:workspace) {FactoryBot.create(:mdm_workspace)}
      let(:flagged_event) { FactoryBot.create(:mdm_event, :workspace => workspace, :name => 'flagme', :critical => true, :seen => false) }
      let(:non_critical_event) { FactoryBot.create(:mdm_event, :workspace => workspace, :name => 'dontflagmebro', :critical => false, :seen => false) }

      before(:example) do
        flagged_event
        non_critical_event
      end

      it 'should included critical unseen events' do
        expect(Mdm::Event.flagged).to eq [flagged_event]
      end
      it 'should exclude non-critical events' do
        expect(Mdm::Event.flagged).not_to include(non_critical_event)
      end

      it 'should exclude critical seen events' do
        flagged_event.seen = true
        flagged_event.save
        expect(Mdm::Event.flagged).not_to include(flagged_event)
      end
    end

    context 'module_run' do
      it 'should only return module_run events' do
        flagged_event = FactoryBot.create(:mdm_event, :name => 'module_run')
        non_critical_event = FactoryBot.create(:mdm_event, :name => 'dontflagmebro')
        flagged_set = Mdm::Event.module_run
        expect(flagged_set).to include(flagged_event)
        expect(flagged_set).not_to include(non_critical_event)
      end
    end
  end

  context 'validations' do
    it 'should require name' do
      unnamed_event = FactoryBot.build(:mdm_event, :name => nil)
      expect(unnamed_event).not_to be_valid
      expect(unnamed_event.errors[:name]).to include("can't be blank")
    end
  end

  context 'factory' do
    it 'should be valid' do
      event = FactoryBot.build(:mdm_event)
      expect(event).to be_valid
    end
  end

end
