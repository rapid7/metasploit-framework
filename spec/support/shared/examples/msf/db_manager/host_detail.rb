RSpec.shared_examples_for 'Msf::DBManager::HostDetail' do
  it { is_expected.to respond_to :report_host_details }
end