RSpec.shared_examples_for 'Msf::DBManager::Service' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :delete_service }
    it { is_expected.to respond_to :each_service }
    it { is_expected.to respond_to :get_service }
  end

  it { is_expected.to respond_to :find_or_create_service }
  it { is_expected.to respond_to :services }
  it { is_expected.to respond_to :report_service }
end