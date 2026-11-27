require 'spec_helper'

RSpec.describe 'post/windows/gather/forensics/enum_drives' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'post', reference_name: 'windows/gather/forensics/enum_drives')
  end

  let(:disk_size) { 1_099_511_627_776 }
  let(:geometry) { ("\0" * 200).tap { |data| data[24, 8] = [disk_size].pack('Q') } }
  let(:output) { double('output', prompting?: false) }
  let(:kernel32) do
    double(
      'Kernel32',
      CreateFileA: { 'return' => 7 },
      DeviceIoControl: { 'GetLastError' => 0, 'lpOutBuffer' => geometry },
      CloseHandle: { 'return' => true }
    )
  end

  before do
    allow(mod).to receive(:client).and_return(double(railgun: double(kernel32: kernel32)))
    allow(mod).to receive(:user_output).and_return(output)
  end

  describe '#print_device' do
    it 'prints a numeric byte count through the single-message output API and closes the handle' do
      expect(output).to receive(:print_line).with(a_string_ending_with('1099511627776'))
      expect(kernel32).to receive(:CloseHandle).with(7)

      mod.print_device('\\\\.\\PhysicalDrive0')
    end

    context 'when Railgun returns its unavailable-size sentinel' do
      let(:disk_size) { 0x4141414141414141 }

      it 'prints N/A instead of treating the unavailable size as an integer' do
        expect(output).to receive(:print_line).with(a_string_ending_with('N/A'))

        mod.print_device('\\\\.\\PhysicalDrive0')
      end
    end
  end
end
