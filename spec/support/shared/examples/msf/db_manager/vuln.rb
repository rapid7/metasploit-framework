RSpec.shared_examples_for 'Msf::DBManager::Vuln' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :each_vuln }
    it { is_expected.to respond_to :find_vuln_by_refs }
    it { is_expected.to respond_to :find_or_create_vuln }
    it { is_expected.to respond_to :has_vuln? }
    it { is_expected.to respond_to :get_vuln }
    it { is_expected.to respond_to :find_vuln_by_details }
  end

  it { is_expected.to respond_to :report_vuln }
  it { is_expected.to respond_to :vulns }
end