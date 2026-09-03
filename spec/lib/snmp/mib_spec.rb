require 'spec_helper'
require 'snmp/mib'
require 'rbconfig'

RSpec.describe SNMP::MIB do
  describe '.import_module' do
    let(:mib_output) do
      <<~PYTHON
        FILENAME = "safe.mib"
        MIB = {"moduleName": "SAFE-MIB", "nodes": {"safeNode": {"oid": (1, 3, 6, 1)}}}
      PYTHON
    end

    it 'passes a caller-controlled filename to smidump as a separate argument' do
      status = instance_double(Process::Status, success?: true)
      allow(described_class).to receive(:import_supported?).and_return(true)
      expect(described_class).to receive(:capture_command).with('smidump', '-f', 'python', 'name; touch injected').and_return([mib_output, '', status])

      Dir.mktmpdir do |directory|
        expect(described_class.import_module('name; touch injected', directory)).to eq('SAFE-MIB')
      end
    end

    it 'rejects executable expressions in smidump output without evaluating them' do
      status = instance_double(Process::Status, success?: true)
      allow(described_class).to receive(:import_supported?).and_return(true)
      allow(described_class).to receive(:capture_command).and_return(['MIB = Kernel.system("touch injected")', '', status])

      Dir.mktmpdir do |directory|
        expect { described_class.import_module('unsafe.mib', directory) }.to raise_error(SNMP::MIB::InvalidMIBError)
      end
    end

    it 'rejects a module name that would escape the output directory' do
      status = instance_double(Process::Status, success?: true)
      allow(described_class).to receive(:import_supported?).and_return(true)
      allow(described_class).to receive(:capture_command).and_return([mib_output.sub('SAFE-MIB', '../escape'), '', status])

      Dir.mktmpdir do |directory|
        expect { described_class.import_module('unsafe.mib', directory) }.to raise_error(SNMP::MIB::InvalidMIBError)
      end
    end

    it 'bounds converter output while it is being read' do
      stub_const('SNMP::MIB::MAX_CONVERTER_OUTPUT_SIZE', 65_536)
      command = [RbConfig.ruby, '-e', "STDOUT.write('A' * #{SNMP::MIB::MAX_CONVERTER_OUTPUT_SIZE + 1})"]

      expect { described_class.send(:capture_command, *command) }.to raise_error(SNMP::MIB::InvalidMIBError, /too large/)
    end
  end

  describe 'Python literal compatibility' do
    it 'decodes hexadecimal, Unicode, and octal string escapes' do
      mib = described_class.send(:eval_mib_data, 'MIB = {"moduleName":"SAFE-MIB","description":"\\x41\\u00e9\\101","nodes":{}}')

      expect(mib['description']).to eq("A\u00e9A")
    end
  end
end
