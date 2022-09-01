RSpec.shared_examples_for 'Msf::DBManager::HostDetail' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting host detail port")}
  end

  it { is_expected.to respond_to :report_host_details }
end