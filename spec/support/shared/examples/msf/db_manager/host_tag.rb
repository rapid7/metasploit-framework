RSpec.shared_examples_for 'Msf::DBManager::HostTag' do
  it { is_expected.to respond_to :report_host_tag }
end