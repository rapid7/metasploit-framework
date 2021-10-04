require 'rspec'

RHOST_EXAMPLES = [
  '192.168.172.1',
  '192.168.172.1/32',
  'file:foo.txt',
  'example',
  'localhost',
  'example.com',
  'http://example.com',
  'https://example.com:443',
  'https://example.com:443/foo/bar?baz=qux&a=b',
  'cidr:/30:http://multiple_ips.example.com/foo',
  'http://[::ffff:7f00:1]:8000/',
  'smb://example.com/',
  'smb://user@example.com/',
  'smb://user:password@example.com',
  'smb://:@example.com',
  'smb://domain;user:pass@example.com/'
].freeze

# Shared examples to ensure that all command parsing supports the same ways of
# supplying inline datastore values
RSpec.shared_examples_for 'a command which parses datastore values' do |opts|
  context 'when the -o option flag is supplied' do
    it 'shows the help menu when no value is supplied' do
      expect(subject.send(opts[:method_name], ['-o'])).to be_nil
      expect(subject).to have_received(opts[:expected_help_cmd])
    end

    it 'allows setting one value' do
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1'
        }
      }
      expect(subject.send(opts[:method_name], ['-o', 'RHOSTS=192.168.172.1'])).to include(expected_result)
    end

    it 'allows setting multiple options individually' do
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1 192.168.172.2',
          'RPORT' => '1337'
        }
      }
      expect(subject.send(opts[:method_name], ['-o', 'RHOSTS=192.168.172.1', '-o', 'RPORT=1337', '-o', 'rhosts=192.168.172.2'])).to include(expected_result)
    end

    it 'parses the option str directly into its components' do
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1',
          'RPORT' => '1337'
        }
      }
      expect(subject.send(opts[:method_name], ['-o', 'RHOSTS=192.168.172.1,RPORT=1337'])).to include(expected_result)
    end

    it 'handles arguments containing spaces' do
      args = ['-o', 'RHOSTS=http://user:this is a password@example.com']
      expected_result = {
        datastore_options: {
          'RHOSTS' => '"http://user:this is a password@example.com"'
        }
      }
      expect(subject.send(opts[:method_name], args)).to include(expected_result)
    end

    RHOST_EXAMPLES.each do |value|
      it "parses the option str correctly for rhost #{value.inspect}" do
        expected_result = {
          datastore_options: {
            'RHOSTS' => value,
            'RPORT' => '1337'
          }
        }
        expect(subject.send(opts[:method_name], ['-o', "RHOSTS=#{value},RPORT=1337"])).to include(expected_result)
      end
    end

    it 'correctly handles combinations of inline options, arguments, and option str being provided' do
      args = [
        '-o', 'RHOSTS=192.168.172.1,RPORT=1337',
        '192.168.172.2',
        'LPORT=5555'
      ]
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1 192.168.172.2',
          'RPORT' => '1337',
          'LPORT' => '5555'
        }
      }
      expect(subject.send(opts[:method_name], args)).to include(expected_result)
    end
  end

  context 'when arbitrary datastore key value pairs are provided' do
    it 'allows setting one value' do
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1'
        }
      }
      expect(subject.send(opts[:method_name], ['RHOSTS=192.168.172.1'])).to include(expected_result)
    end

    it 'allows setting multiple options individually' do
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1',
          'RPORT' => '1337'
        }
      }
      expect(subject.send(opts[:method_name], ['RHOSTS=192.168.172.1', 'RPORT=1337'])).to include(expected_result)
    end

    it 'correctly handles a missing value' do
      expected_result = {
        datastore_options: {
          'RPORT' => ''
        }
      }
      expect(subject.send(opts[:method_name], ['RPORT='])).to include(expected_result)
    end

    it 'handles multiple values' do
      args = ['RHOSTS=192.168.172.1', 'rhosts=192.168.172.2', 'rhost=smb://user:a b c@example.com']
      expected_result = {
        datastore_options: {
          'RHOSTS' => '192.168.172.1 192.168.172.2 "smb://user:a b c@example.com"'
        }
      }
      expect(subject.send(opts[:method_name], args)).to include(expected_result)
    end

    it 'handles whitespaces' do
      args = ['rhosts=http://user:this is a password@example.com', 'http://user:password@example.com']
      expected_result = {
        datastore_options: {
          'RHOSTS' => '"http://user:this is a password@example.com" http://user:password@example.com'
        }
      }
      expect(subject.send(opts[:method_name], args)).to include(expected_result)
    end
  end

  context 'when arguments that resemble an RHOST value are used' do
    it 'handles arguments containing spaces' do
      args = ['http://user:this is a password@example.com', 'http://user:password@example.com']
      expected_result = {
        datastore_options: {
          'RHOSTS' => '"http://user:this is a password@example.com" http://user:password@example.com'
        }
      }
      expect(subject.send(opts[:method_name], args)).to include(expected_result)
    end

    RHOST_EXAMPLES.each do |value|
      it "works with a single value of #{value}" do
        expected_result = {
          datastore_options: {
            'RHOSTS' => value
          }
        }
        expect(subject.send(opts[:method_name], [value])).to include(expected_result)
      end

      it 'works with multiple values' do
        expected_result = {
          datastore_options: {
            'RHOSTS' => "#{value} #{value} #{value}"
          }
        }
        expect(subject.send(opts[:method_name], [value, value, value])).to include(expected_result)
      end

      it 'works with arbitrary option values' do
        expected_result = {
          datastore_options: {
            'RHOSTS' => "#{value} #{value}",
            'RPORT' => '2000',
            'LPORT' => '5555'
          }
        }
        expect(subject.send(opts[:method_name], ['-o', "RHOSTS=#{value}", '-o', 'RPORT=2000', value, 'LPORT=5555'])).to include(expected_result)
      end
    end
  end
end

RSpec.shared_examples_for 'a command which shows help menus' do |opts|
  it 'shows the help menu with the -h flag' do
    expect(subject.send(opts[:method_name], ['-h'])).to be_nil
    expect(subject).to have_received(opts[:expected_help_cmd])
  end

  it 'shows the help menu with --help flag' do
    expect(subject.send(opts[:method_name], ['--help'])).to be_nil
    expect(subject).to have_received(opts[:expected_help_cmd])
  end

  [
    ['--foo'],
    ['--foo', 'bar'],
  ].each do |args|
    it "shows the help menu with unknown flags #{args.inspect}" do
      expect(subject.send(opts[:method_name], args)).to be_nil
      expect(subject).to have_received(opts[:expected_help_cmd])
    end
  end
end

RSpec.describe Msf::Ui::Console::ModuleArgumentParsing do
  include_context 'Msf::UIDriver'

  let(:framework) { nil }
  let(:subject) do
    described_class = self.described_class
    dummy_class = Class.new do
      include Msf::Ui::Console::ModuleCommandDispatcher
      include described_class

      # Method not provided by the mixin, needs to be implemented by class that mixes in described_class
      def cmd_run_help
        # noop
      end

      # Method not provided by the mixin, needs to be implemented by class that mixes in described_class
      def cmd_exploit_help
        # noop
      end
    end
    instance = dummy_class.new(driver)
    instance
  end

  before do
    allow(subject).to receive(:cmd_run_help)
    allow(subject).to receive(:cmd_exploit_help)
    allow(subject).to receive(:cmd_check_help)
  end

  describe '#parse_check_opts' do
    let(:current_mod) { instance_double Msf::Auxiliary, datastore: {} }

    before do
      allow(subject).to receive(:mod).and_return(current_mod)
    end

    it_behaves_like 'a command which parses datastore values',
                    method_name: 'parse_check_opts',
                    expected_help_cmd: 'cmd_check_help'

    it_behaves_like 'a command which shows help menus',
                    method_name: 'parse_check_opts',
                    expected_help_cmd: 'cmd_check_help'
  end

  describe '#parse_run_opts' do
    let(:current_mod) { instance_double Msf::Auxiliary, datastore: {} }

    before do
      allow(subject).to receive(:mod).and_return(current_mod)
    end

    it_behaves_like 'a command which parses datastore values',
                    method_name: 'parse_run_opts',
                    expected_help_cmd: 'cmd_run_help'

    it_behaves_like 'a command which shows help menus',
                    method_name: 'parse_run_opts',
                    expected_help_cmd: 'cmd_run_help'

    it 'handles an action being supplied' do
      args = []
      expected_result = {
        jobify: false,
        quiet: false,
        action: 'action-name',
        datastore_options: {}
      }
      expect(subject.parse_run_opts(args, action: 'action-name')).to eq(expected_result)
    end

    it 'handles an action being specified from the original datastore value' do
      current_mod.datastore['action'] = 'datastore-action-name'
      args = []
      expected_result = {
        jobify: false,
        quiet: false,
        action: 'action-name',
        datastore_options: {}
      }
      expect(subject.parse_run_opts(args, action: 'action-name')).to eq(expected_result)
    end

    it 'handles an action being nil' do
      args = []
      expected_result = {
        jobify: false,
        quiet: false,
        action: nil,
        datastore_options: {}
      }
      expect(subject.parse_run_opts(args)).to eq(expected_result)
    end
  end

  describe '#parse_exploit_opts' do
    let(:current_mod) { instance_double Msf::Exploit, datastore: {} }

    before do
      allow(subject).to receive(:mod).and_return(current_mod)
    end

    it_behaves_like 'a command which parses datastore values',
                    method_name: 'parse_exploit_opts',
                    expected_help_cmd: 'cmd_exploit_help'

    it_behaves_like 'a command which shows help menus',
                    method_name: 'parse_exploit_opts',
                    expected_help_cmd: 'cmd_exploit_help'

    it 'handles no arguments being supplied' do
      args = []
      expected_result = {
        jobify: false,
        quiet: false,
        datastore_options: {}
      }
      expect(subject.parse_exploit_opts(args)).to eq(expected_result)
    end

    it 'allows multiple exploit options to be set' do
      args = [
        # encoder
        '-e', 'encoder_value',
        # force
        '-f',
        # quiet
        '-q',
        # nop
        '-n', 'nop_value',
        # option str
        '-o', 'RPORT=9001',
        # payload
        '-p', 'payload_value',
        # target
        '-t', '5',
        # run in the background
        '-z',
        # inline option
        'LPORT=5555',
        # rhosts
        '192.168.172.1',
        '192.168.172.2',
        'example.com'
      ]
      expected_result = {
        jobify: false,
        quiet: true,
        datastore_options: {
          'RHOSTS' => '192.168.172.1 192.168.172.2 example.com',
          'RPORT' => '9001',
          'LPORT' => '5555'
        },
        encoder: 'encoder_value',
        force: true,
        nop: 'nop_value',
        payload: 'payload_value',
        target: 5,
        background: true
      }
      expect(subject.parse_exploit_opts(args)).to eq(expected_result)
    end
  end
end
