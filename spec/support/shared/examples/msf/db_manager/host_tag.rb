RSpec.shared_examples_for 'Msf::DBManager::HostTag' do

  if ENV['REMOTE_DB']
    before {skip("")}
  end

  it { is_expected.to respond_to :report_host_tag }
end