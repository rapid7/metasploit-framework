# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/mysql/client'

RSpec.describe Rex::Proto::MySQL::Client do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }
  let(:db_name) { 'my_db_name' }

  subject do
    addr_info = instance_double(Addrinfo, ip_address: host, ip_port: port)
    socket = instance_double(Socket, remote_address: addr_info)
    client = described_class.new(io: socket)
    allow(client).to receive(:session_track).and_return({ 1 => [db_name] })
    client
  end

  it { is_expected.to be_a ::Mysql }

  it_behaves_like 'session compatible SQL client'

  describe '#current_database' do
    context 'we have not selected a database yet' do
      before(:each) do
        allow(subject).to receive(:session_track).and_return({})
      end

      it 'returns an empty database name' do
        expect(subject.current_database).to eq('')
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
      { info: 'unix', expected: Msf::Platform::Unix.realname },
      { info: 'solaris', expected: Msf::Platform::Solaris.realname },
      { info: '', expected: '' },
      { info: 'blank', expected: 'blank' },
      { info: nil, expected: '' },
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
      { info: '', expected: '' },
      { info: 'blank', expected: 'blank' },
      { info: nil, expected: '' },
    ].each do |test|
      it "correctly identifies '#{test[:info]}' as '#{test[:expected]}'" do
        expect(subject.map_compile_arch_to_architecture(test[:info])).to eq(test[:expected])
      end
    end
  end
end
