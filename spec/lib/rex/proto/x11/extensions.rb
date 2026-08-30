# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::X11::Extension do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend described_class

    mod.send(:initialize)
    mod
  end

  let(:query_extension) do
    "\x62\x00\x05\x00\f\x00\x00\x00BIG-REQUESTS"
  end

  let(:query_extension2) do
    "\x62\x00\x05\x00\t\x00\x00\x00XKEYBOARD\x00\x00\x00"
  end

  let(:query_extension_resp) do
    "\x01\x00\x01\x00\x00\x00\x00\x00\x01\x86\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  end

  let(:enable_134) do
    "\x86\x00\x01\x00"
  end

  let(:enable_resp) do
    "\x01\x00\x02\x00\x00\x00\x00\x00\xff\xff\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  end

  describe 'X11QueryExtensionRequest' do
    context '#read long length' do
      it do
        request = Rex::Proto::X11::Extension::X11QueryExtensionRequest.read(query_extension)
        expect(request.extension).to eq('BIG-REQUESTS')
      end
    end
    context '#initialize long length' do
      it do
        request = Rex::Proto::X11::Extension::X11QueryExtensionRequest.new(extension: 'BIG-REQUESTS')
        expect(request.to_binary_s).to eq(query_extension)
      end
    end
    context '#read short length' do
      it do
        request = Rex::Proto::X11::Extension::X11QueryExtensionRequest.read(query_extension2)
        expect(request.extension).to eq('XKEYBOARD')
      end
    end
    context '#initialize short length' do
      it do
        request = Rex::Proto::X11::Extension::X11QueryExtensionRequest.new(extension: 'XKEYBOARD')
        expect(request.to_binary_s).to eq(query_extension2)
      end
    end
  end

  describe 'X11QueryExtensionResponse' do
    context '#read' do
      it do
        response = Rex::Proto::X11::Extension::X11QueryExtensionResponse.read(query_extension_resp)
        expect(response.major_opcode).to eq(134)
        expect(response.present).to eq(1)
      end
    end
  end

  describe 'X11ExtensionToggleRequest' do
    context '#read' do
      it do
        request = Rex::Proto::X11::Extension::X11ExtensionToggleRequest.read(enable_134)
        expect(request.opcode).to eq(134)
        expect(request.wanted_major).to eq(0)
        expect(request.wanted_major).to eq(0)
        expect(request.request_length).to eq(1)
      end
    end
    context '#initialize' do
      it do
        request = Rex::Proto::X11::Extension::X11ExtensionToggleRequest.new(opcode: 134)
        expect(request.to_binary_s).to eq(enable_134)
      end
    end
  end

  describe 'X11ExtensionToggleReply' do
    context '#read' do
      it do
        request = Rex::Proto::X11::Extension::X11ExtensionToggleReply.read(enable_resp)
        expect(request.reply_sequence_number).to eq(2)
        expect(request.maximum_request_length).to eq(4194303)
      end
    end
  end
end
