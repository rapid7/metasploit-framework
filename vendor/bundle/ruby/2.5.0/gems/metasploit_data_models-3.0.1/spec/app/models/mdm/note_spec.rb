RSpec.describe Mdm::Note, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      note = FactoryBot.build(:mdm_note)
      expect(note).to be_valid
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:workspace_id).of_type(:integer).with_options(:null => false, :default =>1) }
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:service_id).of_type(:integer) }
      it { is_expected.to have_db_column(:vuln_id).of_type(:integer) }
      it { is_expected.to have_db_column(:ntype).of_type(:string) }
      it { is_expected.to have_db_column(:critical).of_type(:boolean) }
      it { is_expected.to have_db_column(:seen).of_type(:boolean) }
      it { is_expected.to have_db_column(:data).of_type(:text) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      note = FactoryBot.create(:mdm_note)
      expect {
        note.destroy
      }.to_not raise_error
      expect {
        note.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'associations' do
    it { is_expected.to belong_to(:workspace).class_name('Mdm::Workspace') }
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
    it { is_expected.to belong_to(:vuln).class_name('Mdm::Vuln') }
  end

  context 'scopes' do
    context 'flagged' do
      it 'should exclude non-critical note' do
        flagged_note = FactoryBot.create(:mdm_note, :critical => true, :seen => false)
        non_critical_note = FactoryBot.create(:mdm_note, :critical => false, :seen => false)
        flagged_set = Mdm::Note.flagged
        expect(flagged_set).to include(flagged_note)
        expect(flagged_set).not_to include(non_critical_note)
      end

      it 'should exclude seen notes' do
        flagged_note = FactoryBot.create(:mdm_note, :critical => true, :seen => false)
        non_critical_note = FactoryBot.create(:mdm_note, :critical => false, :seen => true)
        flagged_set = Mdm::Note.flagged
        expect(flagged_set).to include(flagged_note)
        expect(flagged_set).not_to include(non_critical_note)
      end
    end

    context 'visible' do
      it 'should only include visible notes' do
        flagged_note = FactoryBot.create(:mdm_note, :ntype => 'flag.me', :critical => true, :seen => false)
        webform_note = FactoryBot.create(:mdm_note, :ntype => 'web.form', :critical => true, :seen => false)
        visible_set = Mdm::Note.visible
        expect(visible_set).to include(flagged_note)
        expect(visible_set).not_to include(webform_note)
      end
    end

    context 'search' do
      it 'should match on ntype' do
        flagged_note = FactoryBot.create(:mdm_note, :ntype => 'flag.me', :critical => true, :seen => false)
        expect(Mdm::Note.search('flag.me')).to include(flagged_note)
      end

      it 'should match on host name' do
        flagged_note = FactoryBot.create(:mdm_note, :seen => false)
        host_name = flagged_note.host.name
        expect(Mdm::Note.search(host_name)).to include(flagged_note)
      end
    end
  end
end
