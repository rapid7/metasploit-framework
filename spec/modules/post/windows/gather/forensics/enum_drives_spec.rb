require 'spec_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/def_kernel32'

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

  context 'when serializing geometry queries' do
    let(:railgun_library) do
      railgun = Rex::Post::Meterpreter::Extensions::Stdapi::Railgun
      railgun::Def::Def_windows_kernel32.create_library(railgun::ConstManager.new)
    end

    shared_examples 'a synchronous query with a null OVERLAPPED pointer' do |errors|
      it 'sends a literal null pointer rather than a zero-length native buffer' do
        calls = 0
        allow(mod).to receive(:print_line)
        allow(kernel32).to receive(:DeviceIoControl) do |*arguments|
          packet, layouts = railgun_library.build_packet_and_layouts(
            Rex::Post::Meterpreter::Packet.new,
            railgun_library.get_function('DeviceIoControl'),
            arguments,
            Rex::Arch::ARCH_X64
          )

          expect(layouts[:inout]).to be_empty
          stack = packet.get_tlv_value(Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::TLV_TYPE_RAILGUN_STACKBLOB)
          expect(stack.unpack('Q<*').last(2)).to eq([0, 0])

          response = { 'GetLastError' => errors.fetch(calls), 'lpOutBuffer' => geometry }
          calls += 1
          response
        end

        mod.print_device('\\\\.\\PhysicalDrive0')

        expect(calls).to eq(errors.length)
      end
    end

    include_examples 'a synchronous query with a null OVERLAPPED pointer', [0]

    context 'when Windows reports an invalid handle and the query is retried' do
      include_examples 'a synchronous query with a null OVERLAPPED pointer', [6, 0]
    end
  end
end
