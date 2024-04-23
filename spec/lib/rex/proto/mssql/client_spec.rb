# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/mysql/client'

RSpec.describe Rex::Proto::MSSQL::Client do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }
  let(:db_name) { 'my_db_name' }
  let(:framework_module) { ::Msf::Module.new }

  subject do
    client = described_class.new(framework_module, nil, host, port)
    client.current_database = db_name
    client
  end

  it_behaves_like 'session compatible SQL client'

  describe '#map_compile_os_to_platform' do
    [
      { info: 'linux', expected: Msf::Platform::Linux.realname },
      { info: 'windows', expected: Msf::Platform::Windows.realname },
      { info: 'win', expected: Msf::Platform::Windows.realname },
    ].each do |test|
      it "correctly identifies '#{test[:info]}' as '#{test[:expected]}'" do
        expect(subject.map_compile_os_to_platform(test[:info])).to eq(test[:expected])
      end
    end
  end

  describe '#map_compile_arch_to_architecture' do
    [
      { info: 'x64', expected: ARCH_X86_64 },
      { info: 'x86', expected: ARCH_X86 },
      { info: '64', expected: ARCH_X86_64 },
      { info: '32-bit', expected: ARCH_X86 },
    ].each do |test|
      it "correctly identifies '#{test[:info]}' as '#{test[:expected]}'" do
        expect(subject.map_compile_arch_to_architecture(test[:info])).to eq(test[:expected])
      end
    end
  end

  describe '#detect_platform_and_arch' do
    [
      { version: 'Microsoft SQL Server 2022 (RTM-CU12) (KB5033663) - 16.0.4115.5 (X64) Mar  4 2024 08:56:10 Copyright (C) 2022 Microsoft Corporation Developer Edition (64-bit) on Linux (Ubuntu 22.04.4 LTS) <X64>', expected: { arch: 'x86_64', platform: 'Linux' } },
      { version: 'Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64) Oct  8 2022 05:58:25 Copyright (C) 2022 Microsoft Corporation Developer Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)', expected: { arch: 'x86_64', platform: 'Windows' } },
    ].each do |test|
      context "when the database is version #{test[:version]}" do
        it "returns #{test[:expected]}" do
          mock_query_result = { rows: [[test[:version]]] }
          allow(subject).to receive(:query).with('select @@version').and_return(mock_query_result)

          expect(subject.detect_platform_and_arch).to eq test[:expected]
        end
      end
    end
  end
  describe '#current_database' do
    context 'we have not selected a database yet' do
      subject do
        described_class.new(framework_module, nil, host, port)
      end

      it 'returns an empty database name' do
        expect(subject.current_database).to eq('')
      end
    end
  end
end
