RSpec.shared_examples_for 'Msf::DBManager::SessionEvent' do
  it { is_expected.to respond_to :session_events }
  it { is_expected.to respond_to :report_session_event }
end