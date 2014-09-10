shared_examples_for 'Metasploit::Framework::LoginScanner::RexSocket' do
  subject(:login_scanner) { described_class.new }

  it { should respond_to :send_delay }
  it { should respond_to :max_send_size }
  it { should respond_to :ssl }
  it { should respond_to :ssl_version }

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
