RSpec.describe Mdm::Session, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      session = FactoryBot.build(:mdm_session)
      expect(session).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      session = FactoryBot.create(:mdm_session)
      expect {
        session.destroy
      }.to_not raise_error
      expect {
        session.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:closed_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:last_seen).of_type(:datetime) }
      it { is_expected.to have_db_column(:opened_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:datastore).of_type(:text) }
      it { is_expected.to have_db_column(:desc).of_type(:string) }
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:local_id).of_type(:integer) }
      it { is_expected.to have_db_column(:module_run_id).of_type(:integer) }
      it { is_expected.to have_db_column(:platform).of_type(:string) }
      it { is_expected.to have_db_column(:port).of_type(:integer) }
      it { is_expected.to have_db_column(:stype).of_type(:string) }
      it { is_expected.to have_db_column(:via_exploit).of_type(:string) }
      it { is_expected.to have_db_column(:via_payload).of_type(:string) }
    end
  end

  context 'associations' do
    it { is_expected.to have_many(:events).class_name('Mdm::SessionEvent').dependent(:delete_all) }
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:originating_module_run).class_name('MetasploitDataModels::ModuleRun') }
    it { is_expected.to have_many(:routes).class_name('Mdm::Route').dependent(:delete_all) }
    it { is_expected.to have_many(:target_module_runs).class_name('MetasploitDataModels::ModuleRun') }
    it { is_expected.to have_many(:tasks).class_name('Mdm::Task').through(:task_sessions)}
    it { is_expected.to have_many(:task_sessions).class_name('Mdm::TaskSession').dependent(:destroy) }
    it { is_expected.to have_one(:workspace).class_name('Mdm::Workspace').through(:host) }
  end

  context 'scopes' do
    context 'alive' do
      it 'should return sessions that have not been closed' do
        alive_session = FactoryBot.create(:mdm_session)
        dead_session = FactoryBot.create(:mdm_session, :closed_at => Time.now)
        alive_set = Mdm::Session.alive
        expect(alive_set).to include(alive_session)
        expect(alive_set).not_to include(dead_session)
      end
    end

    context 'dead'  do
      it 'should return sessions that have been closed' do
        alive_session = FactoryBot.create(:mdm_session)
        dead_session = FactoryBot.create(:mdm_session, :closed_at => Time.now)
        dead_set = Mdm::Session.dead
        expect(dead_set).not_to include(alive_session)
        expect(dead_set).to include(dead_session)
      end
    end

    context 'upgradeable' do
      it 'should return sessions that can be upgraded to meterpreter' do
        win_shell = FactoryBot.create(:mdm_session, :stype => 'shell', :platform => 'Windows')
        linux_shell = FactoryBot.create(:mdm_session, :stype => 'shell', :platform => 'Linux')
        win_meterp = FactoryBot.create(:mdm_session, :stype => 'meterpreter', :platform => 'Windows')
        upgrade_set = Mdm::Session.upgradeable
        expect(upgrade_set).to include(win_shell)
        expect(upgrade_set).not_to include(linux_shell)
        expect(upgrade_set).not_to include(win_meterp)
      end
    end
  end

  context 'callbacks' do
    context 'before_destroy' do
      it 'should call #stop' do
        mysession = FactoryBot.create(:mdm_session)
        expect(mysession).to receive(:stop)
        mysession.destroy
      end
    end
  end

  context 'methods' do
    context '#upgradeable?' do
      it 'should return true for windows shells' do
        win_shell = FactoryBot.create(:mdm_session, :stype => 'shell', :platform => 'Windows')
        expect(win_shell.upgradeable?).to eq(true)
      end

      it 'should return false for non-windows shells' do
        linux_shell = FactoryBot.create(:mdm_session, :stype => 'shell', :platform => 'Linux')
        expect(linux_shell.upgradeable?).to eq(false)
      end

      it 'should return false for Windows Meterpreter Sessions' do
        win_meterp = FactoryBot.create(:mdm_session, :stype => 'meterpreter', :platform => 'Windows')
        expect(win_meterp.upgradeable?).to eq(false)
      end
    end
  end
end
