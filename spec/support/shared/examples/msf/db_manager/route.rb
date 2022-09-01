RSpec.shared_examples_for 'Msf::DBManager::Route' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting evaluation")}
  end

  it { is_expected.to respond_to :report_session_route }
  it { is_expected.to respond_to :report_session_route_remove }
end