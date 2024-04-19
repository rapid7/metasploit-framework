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

  subject do
    allow(socket).to receive(:<<)
    allow(Msf::Db::PostgresPR::Message).to receive(:read).and_return(message)
    allow(Rex::Socket).to receive(:create).and_return(socket)
    client = described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}")
    client
  end

  it_behaves_like 'session compatible SQL client'

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
      { version: 'PostgreSQL 14.11 (Homebrew) on x86_64-apple-darwin22.6.0, compiled by Apple clang version 15.0.0 (clang-1500.1.0.2.5), 64-bit', expected: { arch: 'x86_64', platform: 'OSX' } }
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
