RSpec.shared_examples_for 'Msf::DBManager::VulnDetail' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting evaluation")}
  end

  it { is_expected.to respond_to :report_vuln_details }
  it { is_expected.to respond_to :update_vuln_details }
end