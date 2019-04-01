RSpec.shared_examples_for 'Msf::DBManager::Web' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting web port")}
  end

  it { is_expected.to respond_to :report_web_form }
  it { is_expected.to respond_to :report_web_page }
  it { is_expected.to respond_to :report_web_site }
  it { is_expected.to respond_to :report_web_vuln }
end