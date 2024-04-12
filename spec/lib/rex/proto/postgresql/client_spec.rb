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
      { info: 'arm', expected: ARCH_AARCH64 },
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
end
