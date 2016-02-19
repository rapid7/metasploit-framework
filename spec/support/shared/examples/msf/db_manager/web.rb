RSpec.shared_examples_for 'Msf::DBManager::Web' do
  it { is_expected.to respond_to :report_web_form }
  it { is_expected.to respond_to :report_web_page }
  it { is_expected.to respond_to :report_web_site }
  it { is_expected.to respond_to :report_web_vuln }
end