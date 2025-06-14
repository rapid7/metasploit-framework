require 'spec_helper'

RSpec.describe Msf::Post::Vcenter::Database do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Vcenter::Database)
    mod
  end

  describe '#process_pgpass_file' do
    context 'when the file does not exist' do
      it 'returns nil' do
        allow(subject).to receive(:file_exist?).and_return(false)
        expect(subject.process_pgpass_file).to be_nil
      end
    end

    context 'when the file is empty' do
      it 'returns nil' do
        allow(subject).to receive(:file_exist?).and_return(true)
        allow(subject).to receive(:read_file).and_return('')
        expect(subject.process_pgpass_file).to be_nil
      end
    end

    context 'when the file has several credentials' do
      it 'returns a list of hashes with the credentials' do
        allow(subject).to receive(:file_exist?).and_return(true)
        allow(subject).to receive(:read_file).and_return('localhost:5432:replication:replicator:BN^qgk&a)Ee2dK@|
127.0.0.1:5432:replication:replicator:BN^qgk&a)Ee2dK@|
/var/run/vpostgres:5432:replication:replicator:BN^qgk&a)Ee2dK@|
localhost:5432:postgres:postgres:i23rYgoPBQwpn!5
127.0.0.1:5432:postgres:postgres:i23rYgoPBQwpn!5')
        expect(subject.process_pgpass_file).to eq([
          {
            'database' => 'replication',
            'hostname' => 'localhost',
            'password' => 'BN^qgk&a)Ee2dK@|',
            'port' => '5432',
            'username' => 'replicator'
          },
          {
            'database' => 'replication',
            'hostname' => '127.0.0.1',
            'password' => 'BN^qgk&a)Ee2dK@|',
            'port' => '5432',
            'username' => 'replicator'
          },
          {
            'database' => 'replication',
            'hostname' => '/var/run/vpostgres',
            'password' => 'BN^qgk&a)Ee2dK@|',
            'port' => '5432',
            'username' => 'replicator'
          },
          {
            'database' => 'postgres',
            'hostname' => 'localhost',
            'password' => 'i23rYgoPBQwpn!5',
            'port' => '5432',
            'username' => 'postgres'
          },
          {
            'database' => 'postgres',
            'hostname' => '127.0.0.1',
            'password' => 'i23rYgoPBQwpn!5',
            'port' => '5432',
            'username' => 'postgres'
          }
        ])
      end
    end

    context 'when the file has * for a port in the credentials' do
      it 'returns a list of hashes with the port set to 5432' do
        allow(subject).to receive(:file_exist?).and_return(true)
        allow(subject).to receive(:read_file).and_return('localhost:*:replication:replicator:BN^qgk&a)Ee2dK@|')
        expect(subject.process_pgpass_file).to eq([
          {
            'database' => 'replication',
            'hostname' => 'localhost',
            'password' => 'BN^qgk&a)Ee2dK@|',
            'port' => '5432',
            'username' => 'replicator'
          }
        ])
      end
    end
  end

  describe '#query_pg_shadow_values' do
    context 'when the command does not exist' do
      it 'returns nil' do
        allow(subject).to receive(:command_exists?).and_return(false)
        expect(subject.query_pg_shadow_values('test', 'test', 'test')).to be_nil
      end
    end

    context 'when the command fails to find an entry' do
      it 'returns an empty array' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('this is not valid')
        expect(subject.query_pg_shadow_values('test', 'test', 'test')).to eq([])
      end
    end

    context 'when the command returns several entries' do
      it 'returns an array of hashes with the credentails' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return("postgres|md5fdb13b980a01e3d1ae99b5b55b6e4303\nreplicator|md5c2a01981014a380b63c0c7c66ad77ba9\nvc|md53b5a9fc0dd6c99567e9ca27c459b43d9\nvumuser|md5fc719b1b56f02981027379fd15125feb\ncns|md5d92e4534c059354dee12a7cc9a79faff")
        expect(subject.query_pg_shadow_values('test', 'test', 'test')).to eq([
          { 'password_hash' => 'md5fdb13b980a01e3d1ae99b5b55b6e4303', 'user' => 'postgres' },
          { 'password_hash' => 'md5c2a01981014a380b63c0c7c66ad77ba9', 'user' => 'replicator' },
          { 'password_hash' => 'md53b5a9fc0dd6c99567e9ca27c459b43d9', 'user' => 'vc' },
          { 'password_hash' => 'md5fc719b1b56f02981027379fd15125feb', 'user' => 'vumuser' },
          { 'password_hash' => 'md5d92e4534c059354dee12a7cc9a79faff', 'user' => 'cns' }
        ])
      end
    end

    context 'when the command returns several entries and one has no password hash' do
      it 'returns an array of hashes with the credentails without the hashless credential' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('postgres|md5fdb13b980a01e3d1ae99b5b55b6e4303
  archiver|')
        expect(subject.query_pg_shadow_values('test', 'test', 'test')).to eq([
          { 'password_hash' => 'md5fdb13b980a01e3d1ae99b5b55b6e4303', 'user' => 'postgres' }
        ])
      end
    end
  end

  describe '#query_pg_shadow_values' do
    context 'when the command does not exist' do
      it 'returns nil' do
        allow(subject).to receive(:command_exists?).and_return(false)
        expect(subject.query_vpx_creds('test', 'test', 'test')).to be_nil
      end
    end

    context 'when the command fails to find an entry' do
      it 'returns an empty array' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('this is not valid')
        expect(subject.query_vpx_creds('test', 'test', 'test')).to eq([])
      end
    end

    context 'when the command returns valid entries without a symkey' do
      it 'returns an array of hashes with the credentials' do
        # combination of https://github.com/rapid7/metasploit-framework/pull/16465#issuecomment-1117587575
        # and https://github.com/shmilylty/vhost_password_decrypt
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return("vpxuser|*tktZGW50GH4BEOXyWCr9WTu2PSMGWSvcqEsuAMnwcNuFO/rQPRsOyygRRY/WaM3IOI/BrqcThiaiM3j4Jw+KtA==|192.168.20.20|192.168.20.10|192.168.20.10\nvpxuser|*ZdvmNiLEXzZL/uhdW6Zb4Px4RR72iD+xftdA0n9hJ8xpFNJW/axpyKMQ8BJWIFTzzoxQnAm2PaX486yExLX7qg==|192.168.20.20|192.168.20.15|test1.local")
        expect(subject.query_vpx_creds('test', 'test', 'test')).to eq([
          {
            'dns_name' => '192.168.20.10',
            'encrypted_password' =>
              '*tktZGW50GH4BEOXyWCr9WTu2PSMGWSvcqEsuAMnwcNuFO/rQPRsOyygRRY/WaM3IOI/BrqcThiaiM3j4Jw+KtA==',
            'ip_address' => '192.168.20.10',
            'local_ip' => '192.168.20.20',
            'user' => 'vpxuser'
          },
          {
            'dns_name' => 'test1.local',
            'encrypted_password' =>
            '*ZdvmNiLEXzZL/uhdW6Zb4Px4RR72iD+xftdA0n9hJ8xpFNJW/axpyKMQ8BJWIFTzzoxQnAm2PaX486yExLX7qg==',
            'ip_address' => '192.168.20.15',
            'local_ip' => '192.168.20.20',
            'user' => 'vpxuser'
          }
        ])
      end
    end

    context 'when the command returns valid entries with a symkey' do
      it 'returns an array of hashes with the credentials with a decrypted_password field' do
        # combination of https://github.com/rapid7/metasploit-framework/pull/16465#issuecomment-1117587575
        # and https://github.com/shmilylty/vhost_password_decrypt
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('vpxuser|*SN2otuvNvGRSC29lxhU4XQbgNOMyVawGF4UHA38w2zq59tX0WzkgkQTNBJSJpHvBvkYwyiR8xNAv1oquEOOLvQ==|192.168.20.20|192.168.20.15|test1.local')
        expect(subject.query_vpx_creds('test', 'test', 'test', 'f1d0d054e43ac880809c354cec681b3433e36fc4ea6b1480de05b7b86c3506cd')).to eq([
          {
            'dns_name' => 'test1.local',
            'encrypted_password' =>
            '*SN2otuvNvGRSC29lxhU4XQbgNOMyVawGF4UHA38w2zq59tX0WzkgkQTNBJSJpHvBvkYwyiR8xNAv1oquEOOLvQ==',
            'ip_address' => '192.168.20.15',
            'local_ip' => '192.168.20.20',
            'user' => 'vpxuser',
            'decrypted_password' => '-KOU.80J\I0n\Pcqya3F0af=z5Ix-5.u'
          }
        ])
      end
    end

    context 'when the command returns valid entries with an invalid symkey' do
      it 'returns an array of hashes with the credentials with a decrypted_password field' do
        # combination of https://github.com/rapid7/metasploit-framework/pull/16465#issuecomment-1117587575
        # and https://github.com/shmilylty/vhost_password_decrypt
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('vpxuser|*SN2otuvNvGRSC29lxhU4XQbgNOMyVawGF4UHA38w2zq59tX0WzkgkQTNBJSJpHvBvkYwyiR8xNAv1oquEOOLvQ==|192.168.20.20|192.168.20.15|test1.local')
        expect(subject.query_vpx_creds('test', 'test', 'test', 'bad0d054e43ac880809c354cec681b3433e36fc4ea6b1480de05b7b86c3506cd')).to eq([
          {
            'dns_name' => 'test1.local',
            'encrypted_password' =>
            '*SN2otuvNvGRSC29lxhU4XQbgNOMyVawGF4UHA38w2zq59tX0WzkgkQTNBJSJpHvBvkYwyiR8xNAv1oquEOOLvQ==',
            'ip_address' => '192.168.20.15',
            'local_ip' => '192.168.20.20',
            'user' => 'vpxuser'
          }
        ])
      end
    end
  end

  # XXX need to add a real user test
  describe '#get_vpx_users' do
    context 'when the command does not exist' do
      it 'returns nil' do
        allow(subject).to receive(:command_exists?).and_return(false)
        expect(subject.get_vpx_users('test', 'test', 'test', 'test')).to be_nil
      end
    end

    context 'when the command does not return expected content' do
      it 'returns empty array' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('this is not valid')
        expect(subject.get_vpx_users('test', 'test', 'test', 'test')).to eq([])
      end
    end

    context 'when the command succeeds' do
      it 'returns array of hashes with credentials' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('localhost|127.0.0.1|root|*')
        # we need to convert the XML:Doc back to a string so it can be tested correctly
        expect(subject.get_vpx_users('test', 'test', 'test', 'test')).to eq([
          {
            'fqdn' => 'localhost',
            'ip' => '127.0.0.1',
            'user' => 'root',
            'password' => ''
          }
        ])
      end
      # XXX need to add a valid test where we actually decrypt something
    end
  end

  describe '#query_pg_shadow_values' do
    context 'when the command does not exist' do
      it 'returns nil' do
        allow(subject).to receive(:command_exists?).and_return(false)
        expect(subject.get_vpx_customization_spec('test', 'test', 'test')).to be_nil
      end
    end
    context 'when the command doesnt return expected content' do
      it 'returns empty hash' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('this is not valid')
        expect(subject.get_vpx_customization_spec('test', 'test', 'test')).to eq({})
      end
    end
    context 'when the command returns a valid entry' do
      it 'returns a valid processed XML doc' do
        allow(subject).to receive(:command_exists?).and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('<xml></xml>')
        # we need to convert the XML:Doc back to a string so it can be tested correctly
        expect(subject.get_vpx_customization_spec('test', 'test', 'test').map { |k, v| [k.to_s, v.to_s] }.to_h).to eq({ '<xml></xml>' => "<?xml version=\"1.0\"?>\n<xml/>\n" })
      end
    end
  end
end
