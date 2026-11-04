require 'rspec'
require 'msfdb_helpers/db_interface'

RSpec.describe MsfdbHelpers::DbInterface do
  let(:options) do
    { msf_db_name: 'msf', msf_db_user: 'msf', msftest_db_name: 'msftest', msftest_db_user: 'msftest' }
  end
  let(:expected_rules) do
    <<~HBA.lines.map(&:split)
      local "msf" "msf" md5
      host "msf" "msf" 127.0.0.1/32 md5
      host "msf" "msf" ::1/128 md5
      local "msftest" "msftest" md5
      host "msftest" "msftest" 127.0.0.1/32 md5
      host "msftest" "msftest" ::1/128 md5
      local "postgres" "msftest" md5
      host "postgres" "msftest" 127.0.0.1/32 md5
      host "postgres" "msftest" ::1/128 md5
    HBA
  end

  def generated_rules
    described_class.new(options).authentication_config.lines.reject { |line| line.start_with?('#') }.map(&:split).reject(&:empty?)
  end

  it 'only permits the application database/role pairs with passwords over sockets and loopback on Unix' do
    allow(Gem).to receive(:win_platform?).and_return(false)
    expect(generated_rules).to eq(expected_rules)
  end

  it 'only emits the password-protected loopback rules on Windows' do
    allow(Gem).to receive(:win_platform?).and_return(true)
    expect(generated_rules).to eq(expected_rules.reject { |rule| rule.first == 'local' })
  end

  it 'rejects database names that PostgreSQL would interpret as HBA regular expressions' do
    options[:msf_db_name] = '/.*'
    expect { generated_rules }.to raise_error(ArgumentError, /leading slash/)
  end

  it 'rejects role names that PostgreSQL would interpret as HBA regular expressions' do
    options[:msf_db_user] = '/.*'
    expect { generated_rules }.to raise_error(ArgumentError, /leading slash/)
  end

  it 'accepts database and role names at the 63-byte identifier limit' do
    options[:msf_db_name] = 'd' * 63
    options[:msf_db_user] = ('é' * 31) + 'r'
    expect { generated_rules }.not_to raise_error
  end

  it 'rejects database names that PostgreSQL would truncate' do
    options[:msf_db_name] = 'd' * 64
    expect { generated_rules }.to raise_error(ArgumentError, /63 bytes/)
  end

  it 'measures the role identifier limit in bytes rather than characters' do
    options[:msf_db_user] = 'é' * 32
    expect { generated_rules }.to raise_error(ArgumentError, /63 bytes/)
  end
end
