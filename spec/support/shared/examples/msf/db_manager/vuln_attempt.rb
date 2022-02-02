RSpec.shared_examples_for 'Msf::DBManager::VulnAttempt' do
  it { is_expected.to respond_to :report_vuln_attempt }
end