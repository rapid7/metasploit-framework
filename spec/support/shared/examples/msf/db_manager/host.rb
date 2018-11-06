RSpec.shared_examples_for 'Msf::DBManager::Host' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :each_host }
    it { is_expected.to respond_to :del_host }
    it { is_expected.to respond_to :has_host? }
  end

  it { is_expected.to respond_to :find_or_create_host }
  it { is_expected.to respond_to :get_host }
  it { is_expected.to respond_to :hosts }
  it { is_expected.to respond_to :report_host }
end