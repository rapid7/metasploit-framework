# -*- coding: binary -*-

require 'spec_helper'
require 'postgres/postgres-pr/connection'

RSpec.describe Msf::Db::PostgresPR::Connection do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }
  let(:db_name) { 'my_db_name' }
  let(:socket) { double(Rex::Socket, peerhost: host, peerport: port) }
  let(:message) { Msf::Db::PostgresPR::ReadyForQuery.new('') }

  before do
    allow(socket).to receive(:<<)
    allow(socket).to receive(:write)
    allow(socket).to receive(:read).and_return('S')
    allow(socket).to receive(:extend)
    allow(socket).to receive(:initsock_with_ssl_version)
    allow(Msf::Db::PostgresPR::Message).to receive(:read).and_return(message)
    allow(Rex::Socket).to receive(:create_param).and_return(socket)
  end

  subject do
    described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}")
  end

  it_behaves_like 'session compatible SQL client'

  describe 'SSL connection' do
    let(:ssl_request_message) { instance_double(Msf::Db::PostgresPR::SSLRequest) }
    let(:ssl_opts) { { ssl_version: 'TLS1.2', ssl_verify_mode: 'peer', ssl_cipher: 'AES256' } }

    before do
      allow(Msf::Db::PostgresPR::SSLRequest).to receive(:new).with(80877103).and_return(ssl_request_message)
      allow(ssl_request_message).to receive(:dump).and_return('ssl_request_data')
    end

    context 'when SSL is enabled and server supports SSL' do
      it 'successfully establishes SSL connection' do
        allow(socket).to receive(:read).with(1).and_return('S')

        expect(socket).to receive(:write).with('ssl_request_data')
        expect(socket).to receive(:extend).with(Rex::Socket::SslTcp)
        expect(socket).to receive(:initsock_with_ssl_version)

        client = described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}", nil, true, ssl_opts)
        expect(client).to be_a(Msf::Db::PostgresPR::Connection)
      end
    end

    context 'when SSL is enabled but server does not support SSL' do
      it 'raises an error when server responds with N' do
        allow(socket).to receive(:read).with(1).and_return('N')

        expect(socket).to receive(:write).with('ssl_request_data')
        expect(socket).not_to receive(:extend)

        expect {
          described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}", nil, true, ssl_opts)
        }.to raise_error("SSL connection requested but server at #{host}:#{port} does not support SSL")
      end
    end

    context 'when SSL is enabled but server responds unexpectedly' do
      it 'raises an error for unexpected SSL response' do
        allow(socket).to receive(:read).with(1).and_return('X')

        expect(socket).to receive(:write).with('ssl_request_data')
        expect(socket).not_to receive(:extend)

        expect {
          described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}", nil, true, ssl_opts)
        }.to raise_error('Unexpected response to SSLRequest: "X"')
      end
    end

    context 'when SSL is disabled' do
      it 'does not attempt SSL handshake' do
        expect(socket).not_to receive(:write).with('ssl_request_data')
        expect(socket).not_to receive(:extend).with(Rex::Socket::SslTcp)

        client = described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}", nil, false, ssl_opts)
        expect(client).to be_a(Msf::Db::PostgresPR::Connection)
      end
    end
  end

  describe '#map_compile_os_to_platform' do
    [
      { info: 'linux', expected: Msf::Platform::Linux.realname },
      { info: 'linux2.6', expected: Msf::Platform::Linux.realname },
      { info: 'debian-linux-gnu', expected: Msf::Platform::Linux.realname },
      { info: 'win', expected: Msf::Platform::Windows.realname },
      { info: 'windows', expected: Msf::Platform::Windows.realname },
      { info: 'darwin', expected: Msf::Platform::OSX.realname },
      { info: 'osx', expected: Msf::Platform::OSX.realname },
      { info: 'macos', expected: Msf::Platform::OSX.realname },
      { info: 'solaris', expected: Msf::Platform::Solaris.realname },
      { info: 'aix', expected: Msf::Platform::AIX.realname },
      { info: 'hpux', expected: Msf::Platform::HPUX.realname },
      { info: 'irix', expected: Msf::Platform::Irix.realname },
    ].each do |test|
      it "correctly identifies '#{test[:info]}' as '#{test[:expected]}'" do
        expect(subject.map_compile_os_to_platform(test[:info])).to eq(test[:expected])
      end
    end
  end

  describe '#map_compile_arch_to_architecture' do
    [
      { info: 'x86_64', expected: ARCH_X86_64 },
      { info: 'x86_x64', expected: ARCH_X86_64 },
      { info: 'x64', expected: ARCH_X86_64 },
      { info: '64', expected: ARCH_X86_64 },
      { info: 'x86', expected: ARCH_X86 },
      { info: '86', expected: ARCH_X86 },
      { info: 'i686', expected: ARCH_X86 },
      { info: 'arm64', expected: ARCH_AARCH64 },
      { info: 'arm', expected: ARCH_ARMLE },
      { info: 'sparc', expected: ARCH_SPARC },
      { info: 'sparc64', expected: ARCH_SPARC64 },
      { info: 'ppc', expected: ARCH_PPC },
      { info: 'mips', expected: ARCH_MIPS },
    ].each do |test|
      it "correctly identifies '#{test[:info]}' as '#{test[:expected]}'" do
        expect(subject.map_compile_arch_to_architecture(test[:info])).to eq(test[:expected])
      end
    end
  end

  describe '#detect_platform_and_arch' do
    [
      { version: 'PostgreSQL 9.4.26 on x86_64-pc-linux-gnu (Debian 9.4.26-1.pgdg90+1), compiled by gcc (Debian 6.3.0-18+deb9u1) 6.3.0 20170516, 64-bit', expected: { arch: 'x86_64', platform: 'Linux' } },
      { version: 'PostgreSQL 14.11 (Debian 14.11-1.pgdg120+2) on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit', expected: { arch: 'x86_64', platform: 'Linux' } },
      { version: 'PostgreSQL 14.11 (Homebrew) on x86_64-apple-darwin22.6.0, compiled by Apple clang version 15.0.0 (clang-1500.1.0.2.5), 64-bit', expected: { arch: 'x86_64', platform: 'OSX' } },
      {
        version: 'PostgreSQL 14.11 (Homebrew) <arch>-<platform>, compiled by <platform> clang version 15.0.0 (clang-1500.1.0.2.5), <arch>',
        expected: {
          arch: 'postgresql 14.11 (homebrew) <arch>-<platform>, compiled by <platform> clang version 15.0.0 (clang-1500.1.0.2.5), <arch>',
          platform: 'postgresql 14.11 (homebrew) <arch>-<platform>, compiled by <platform> clang version 15.0.0 (clang-1500.1.0.2.5), <arch>'
        }
      }
    ].each do |test|
      context "when the database is version #{test[:version]}" do
        it "returns #{test[:expected]}" do
          mock_query_result = instance_double Msf::Db::PostgresPR::Connection::Result, rows: [[test[:version]]]
          allow(subject).to receive(:query).with('select version()').and_return(mock_query_result)

          expect(subject.detect_platform_and_arch).to eq test[:expected]
        end
      end
    end
  end
end
