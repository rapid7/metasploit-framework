RSpec.shared_examples_for 'Msf::DBManager::Client' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting client port")}
  end

  it { is_expected.to respond_to :find_or_create_client }
  it { is_expected.to respond_to :get_client }
  it { is_expected.to respond_to :report_client }
end