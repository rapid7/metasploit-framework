RSpec.shared_examples_for 'Metasploit::Framework::LoginScanner::RexSocket' do
  subject(:login_scanner) { described_class.new }

  it { is_expected.to respond_to :ssl }
  it { is_expected.to respond_to :ssl_version }

end
