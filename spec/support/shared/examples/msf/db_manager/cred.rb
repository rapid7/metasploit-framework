RSpec.shared_examples_for 'Msf::DBManager::Cred' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting cred port")}
  end

  it { is_expected.to respond_to :creds }
  it { is_expected.to respond_to :each_cred }
  it { is_expected.to respond_to :find_or_create_cred }
  it { is_expected.to respond_to :report_auth }
  it { is_expected.to respond_to :report_auth_info }
  it { is_expected.to respond_to :report_cred }
end