RSpec.shared_examples_for 'Msf::DBManager::Route' do
  it { is_expected.to respond_to :report_session_route }
  it { is_expected.to respond_to :report_session_route_remove }
end