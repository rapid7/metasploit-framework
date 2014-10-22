shared_examples_for 'Metasploit::Framework::LoginScanner::RexSocket' do
  subject(:login_scanner) { described_class.new }

  it { should respond_to :ssl }
  it { should respond_to :ssl_version }

end
