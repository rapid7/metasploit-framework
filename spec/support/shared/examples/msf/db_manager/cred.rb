RSpec.shared_examples_for 'Msf::DBManager::Cred' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :each_cred }
    it { is_expected.to respond_to :find_or_create_cred }
    it { is_expected.to respond_to :report_auth }
    it { is_expected.to respond_to :report_auth_info }
    it { is_expected.to respond_to :report_cred }
  end

  it { is_expected.to respond_to :creds }
  it { is_expected.to respond_to :create_credential }
  it { is_expected.to respond_to :update_credential }
  it { is_expected.to respond_to :delete_credentials }
end