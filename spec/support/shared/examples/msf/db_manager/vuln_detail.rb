RSpec.shared_examples_for 'Msf::DBManager::VulnDetail' do
  it { is_expected.to respond_to :report_vuln_details }
  it { is_expected.to respond_to :update_vuln_details }
end