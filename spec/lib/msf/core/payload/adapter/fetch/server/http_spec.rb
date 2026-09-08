require 'spec_helper'

RSpec.describe Msf::Payload::Adapter::Fetch::Server::HTTP do
  let(:harness_class) do
    Class.new do
      include Msf::Payload::Adapter::Fetch::Server::HTTP

      def register_advanced_options(*); end
      def print_error(*); end
      def print_warning(*); end
      def print_status(*); end
      def vprint_status(*); end
      def generate(opts = {}); end
    end
  end

  subject(:harness) { harness_class.new }

  describe '#identify_arch' do
    context 'when the arch query param is missing' do
      it 'prints an error and returns nil' do
        expect(harness).to receive(:print_error).with(/missing required arch/)
        expect(harness.identify_arch({})).to be_nil
      end
    end

    context 'when the arch query param is blank' do
      it 'prints an error and returns nil' do
        expect(harness).to receive(:print_error).with(/missing required arch/)
        expect(harness.identify_arch({ 'arch' => '  ' })).to be_nil
      end
    end

    context 'when the arch is unambiguous' do
      it 'maps a plain x86_64 uname string to x64' do
        expect(harness.identify_arch({ 'arch' => 'x86_64' })).to eq(Rex::Arch::ARCH_X64)
      end

      it 'maps aarch64 to aarch64' do
        expect(harness.identify_arch({ 'arch' => 'aarch64' })).to eq(Rex::Arch::ARCH_AARCH64)
      end

      it 'returns nil for an arch uname does not recognize' do
        expect(harness.identify_arch({ 'arch' => 'not-a-real-arch' })).to be_nil
      end
    end

    context 'when the arch is mips' do
      it 'guesses mipsel and warns when no endian data is present' do
        expect(harness).to receive(:print_warning).at_least(:once)
        expect(harness.identify_arch({ 'arch' => 'mips' })).to eq(Rex::Arch::ARCH_MIPSLE)
      end

      it 'resolves to mipsel when endian is 1 (little)' do
        expect(harness.identify_arch({ 'arch' => 'mips', 'endian' => '1' })).to eq(Rex::Arch::ARCH_MIPSLE)
      end

      it 'resolves to mips (big endian) when endian is 2' do
        expect(harness.identify_arch({ 'arch' => 'mips', 'endian' => '2' })).to eq(Rex::Arch::ARCH_MIPSBE)
      end

      it 'warns and falls back to mipsel for an unrecognized endian value' do
        expect(harness).to receive(:print_warning).with(/Unknown endian value/)
        expect(harness).to receive(:print_warning).at_least(:once)
        expect(harness.identify_arch({ 'arch' => 'mips', 'endian' => '9' })).to eq(Rex::Arch::ARCH_MIPSLE)
      end
    end

    context 'when the arch is mipsel' do
      it 'is unaffected by the mips endian-guessing logic' do
        expect(harness.identify_arch({ 'arch' => 'mipsel', 'endian' => '2' })).to eq(Rex::Arch::ARCH_MIPSLE)
      end
    end

    context 'when a query param is duplicated in the request' do
      it 'uses the first arch value instead of raising on the array' do
        expect(harness.identify_arch({ 'arch' => %w[x86_64 aarch64] })).to eq(Rex::Arch::ARCH_X64)
      end

      it 'uses the first endian value instead of raising on the array' do
        expect(harness.identify_arch({ 'arch' => 'mips', 'endian' => %w[2 1] })).to eq(Rex::Arch::ARCH_MIPSBE)
      end
    end
  end

  describe '#on_request_uri' do
    let(:cli) { double('cli', peerhost: '192.0.2.1') }
    let(:request) { double('request', uri: '/payload', headers: {}, uri_parts: { 'QueryString' => query_string }) }
    let(:query_string) { {} }

    context 'when dynamic_arch is disabled' do
      let(:srv_entry) { { opts: { dynamic_arch: false }, data: 'static-payload-bytes' } }

      it 'sends the static payload data as-is' do
        expect(cli).to receive(:send_response) do |response|
          expect(response.code).to eq(200)
          expect(response.body).to eq('static-payload-bytes')
        end
        harness.on_request_uri(cli, request, srv_entry)
      end
    end

    context 'when dynamic_arch is enabled' do
      let(:srv_entry) { { opts: { dynamic_arch: true } } }

      context 'and the arch query param is missing' do
        let(:query_string) { {} }

        it 'responds 400 Bad Request' do
          expect(cli).to receive(:send_response) do |response|
            expect(response.code).to eq(400)
          end
          harness.on_request_uri(cli, request, srv_entry)
        end
      end

      context 'and the arch cannot be identified' do
        let(:query_string) { { 'arch' => 'not-a-real-arch' } }

        it 'responds 404 Not Found' do
          allow(harness).to receive(:print_error)
          expect(cli).to receive(:send_response) do |response|
            expect(response.code).to eq(404)
          end
          harness.on_request_uri(cli, request, srv_entry)
          expect(harness).to have_received(:print_error).with(/Failed to identify arch/)
        end
      end

      context 'and the endian value for a mips host is unrecognized' do
        let(:query_string) { { 'arch' => 'mips', 'endian' => 'garbage' } }

        it 'falls back to mipsel and generates a payload for it' do
          allow(harness).to receive(:print_warning)
          expect(harness).to receive(:generate).with(hash_including(arch: Rex::Arch::ARCH_MIPSLE)).and_return('exe-bytes')
          expect(cli).to receive(:send_response) do |response|
            expect(response.code).to eq(200)
            expect(response.body).to eq('exe-bytes')
          end
          harness.on_request_uri(cli, request, srv_entry)
        end
      end

      context 'and the arch is identified but no payload is available' do
        let(:query_string) { { 'arch' => 'x86_64' } }

        it 'responds 404 Not Found' do
          expect(harness).to receive(:generate).with(hash_including(arch: Rex::Arch::ARCH_X64)).and_return(nil)
          expect(harness).to receive(:print_error).with(/No payload available/)
          expect(cli).to receive(:send_response) do |response|
            expect(response.code).to eq(404)
          end
          harness.on_request_uri(cli, request, srv_entry)
        end
      end

      context 'and a payload is generated for the identified arch' do
        let(:query_string) { { 'arch' => 'mips', 'endian' => '2' } }

        it 'generates for the disambiguated mips arch and sends it back' do
          expect(harness).to receive(:generate).with(hash_including(arch: Rex::Arch::ARCH_MIPSBE)).and_return('exe-bytes')
          expect(cli).to receive(:send_response) do |response|
            expect(response.code).to eq(200)
            expect(response.body).to eq('exe-bytes')
          end
          harness.on_request_uri(cli, request, srv_entry)
        end
      end

      context 'and the endian query param is absent entirely (e.g. an older/plain wget fetch)' do
        let(:query_string) { { 'arch' => 'mips' } }

        it 'still resolves a valid arch and generates a payload for it' do
          expect(harness).to receive(:generate).with(hash_including(arch: Rex::Arch::ARCH_MIPSLE)).and_return('exe-bytes')
          expect(cli).to receive(:send_response) do |response|
            expect(response.code).to eq(200)
            expect(response.body).to eq('exe-bytes')
          end
          harness.on_request_uri(cli, request, srv_entry)
        end
      end
    end
  end
end
