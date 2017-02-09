
RSpec.shared_examples_for 'Metasploit::Framework::Tcp::Client' do
  subject(:login_scanner) { described_class.new }

  it { is_expected.to respond_to :send_delay }
  it { is_expected.to respond_to :max_send_size }

  before(:example) do
    creds = double('Metasploit::Framework::CredentialCollection')
    allow(creds).to receive(:pass_file)
    allow(creds).to receive(:username)
    allow(creds).to receive(:password)
    allow(creds).to receive(:user_file)
    allow(creds).to receive(:userpass_file)
    allow(creds).to receive(:prepended_creds).and_return([])
    allow(creds).to receive(:additional_privates).and_return([])
    allow(creds).to receive(:additional_publics).and_return(['user'])
    allow(creds).to receive(:empty?).and_return(true)
    login_scanner.cred_details = creds
  end

  context 'send_delay' do
    it 'is not valid for a non-number' do
      login_scanner.send_delay = "a"
      expect(login_scanner).to_not be_valid
      expect(login_scanner.errors[:send_delay]).to include "is not a number"
    end

    it 'is not valid for a floating point' do
      login_scanner.send_delay = 5.76
      expect(login_scanner).to_not be_valid
      expect(login_scanner.errors[:send_delay]).to include "must be an integer"
    end

    it 'is not valid for a negative number' do
      login_scanner.send_delay = -8
      expect(login_scanner).to_not be_valid
      expect(login_scanner.errors[:send_delay]).to include "must be greater than or equal to 0"
    end

    it 'is valid for a legitimate  number' do
      login_scanner.send_delay = rand(1000) + 1
      expect(login_scanner.errors[:send_delay]).to be_empty
    end
  end

  context 'max_send_size' do
    it 'is not valid for a non-number' do
      login_scanner.max_send_size = "a"
      expect(login_scanner).to_not be_valid
      expect(login_scanner.errors[:max_send_size]).to include "is not a number"
    end

    it 'is not valid for a floating point' do
      login_scanner.max_send_size = 5.76
      expect(login_scanner).to_not be_valid
      expect(login_scanner.errors[:max_send_size]).to include "must be an integer"
    end

    it 'is not valid for a negative number' do
      login_scanner.max_send_size = -8
      expect(login_scanner).to_not be_valid
      expect(login_scanner.errors[:max_send_size]).to include "must be greater than or equal to 0"
    end

    it 'is valid for a legitimate  number' do
      login_scanner.max_send_size = rand(1000) + 1
      expect(login_scanner.errors[:max_send_size]).to be_empty
    end
  end

end
