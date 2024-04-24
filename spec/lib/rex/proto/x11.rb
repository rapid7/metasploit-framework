# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Exploit::Remote::X11 do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend described_class

    mod.send(:initialize)
    mod
  end

  let(:get_property_resp) do
    "\x01\x08\x04\x00\x1f\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00" \
    "\x79\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x58\x66\x74\x2e\x64\x70\x69\x3a\x09\x39\x36\x0a\x58\x66\x74\x2e" \
    "\x61\x6e\x74\x69\x61\x6c\x69\x61\x73\x3a\x09\x31\x0a\x58\x66\x74" \
    "\x2e\x68\x69\x6e\x74\x69\x6e\x67\x3a\x09\x31\x0a\x58\x66\x74\x2e" \
    "\x68\x69\x6e\x74\x73\x74\x79\x6c\x65\x3a\x09\x68\x69\x6e\x74\x73" \
    "\x6c\x69\x67\x68\x74\x0a\x58\x66\x74\x2e\x72\x67\x62\x61\x3a\x09" \
    "\x72\x67\x62\x0a\x58\x63\x75\x72\x73\x6f\x72\x2e\x73\x69\x7a\x65" \
    "\x3a\x09\x32\x34\x0a\x58\x63\x75\x72\x73\x6f\x72\x2e\x74\x68\x65" \
    "\x6d\x65\x3a\x09\x59\x61\x72\x75\x0a\x00\x00\x00"
  end

  let(:get_property) do
    "\x14\x00\x06\x00\x28\x05\x00\x00\x17\x00\x00\x00\x1f\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\xe1\xf5\x05"
  end

  let(:creategc) do
    "\x37\x00\x05\x00\x00\x00\x00\x01\x28\x05\x00\x00\x08\x00\x00\x00\xff\xff\xff\x00"
  end

  let(:get_input_focus) do
    "\x2b\x00\x01\x00"
  end

  let(:free_gc) do
    "\x3c\x01\x02\x00\x00\x00\x00\x02"
  end

  let(:intern_atom_wait) do
    "\x10\x00\x03\x00\x04\x00\x00\x00\x57\x61\x69\x74"
  end

  let(:intern_atom_server_overlay_visuals) do
    "\x10\x01\x08\x00\x16\x00\x00\x00\x53\x45\x52\x56\x45\x52\x5f\x4f" \
    "\x56\x45\x52\x4c\x41\x59\x5f\x56\x49\x53\x55\x41\x4c\x53\x00\x00"
  end

  describe 'handles GetProperty response' do
    it do
      response = Msf::Exploit::Remote::X11::X11GetPropertyResponse.read(get_property_resp)
      expect(response.get_property_type).to eq(31) # \x1f\x00\x00\x00
      expect(response.sequence_number).to eq(4) # \x04\x00
      expect(response.value_data).to eq("Xft.dpi:\t96\nXft.antialias:\t1\nXft.hinting:\t1\nXft.hintstyle:\thintslight\nXft.rgba:\trgb\nXcursor.size:\t24\nXcursor.theme:\tYaru\n")
    end
  end

  describe 'handles GetProperty request' do
    it do
      request = Msf::Exploit::Remote::X11::X11GetPropertyRequest.new(window: 1320)
      expect(request.to_binary_s).to eq(get_property)
      request = Msf::Exploit::Remote::X11::X11GetPropertyRequest.read(get_property)
      expect(request.content_length).to eq(100_000_000)
      expect(request.window).to eq(1320)
    end
  end

  describe 'creates a graphical context request' do
    it do
      request = Msf::Exploit::Remote::X11::X11CreateGraphicalContextRequest.read(creategc)
      expect(request.opcode).to eq(55)
      expect(request.request_length).to eq(5)
      expect(request.cid).to eq(16777216)
      expect(request.drawable).to eq(1320)
      expect(request.gc_value_mask_background).to eq(1)
      expect(request.background).to eq(16777215)
      request = Msf::Exploit::Remote::X11::X11CreateGraphicalContextRequest.new(
        cid: 16777216,
        drawable: 1320,
        gc_value_mask_background: 1
      )
      expect(request.to_binary_s).to eq(creategc)
    end
  end

  describe 'handles GetInputFocus request' do
    it do
      request = Msf::Exploit::Remote::X11::X11GetInputFocusRequest.new
      expect(request.to_binary_s).to eq(get_input_focus)
      request = Msf::Exploit::Remote::X11::X11GetInputFocusRequest.read(get_input_focus)
      expect(request.opcode).to eq(43)
    end
  end

  describe 'handles FreeGraphicalContext request' do
    it do
      request = Msf::Exploit::Remote::X11::X11FreeGraphicalContextRequest.new(
        gc: 33554432
      )
      expect(request.to_binary_s).to eq(free_gc)
      request = Msf::Exploit::Remote::X11::X11FreeGraphicalContextRequest.read(free_gc)
      expect(request.opcode).to eq(60)
      expect(request.gc).to eq(33554432)
    end
  end

  describe 'creates InternAtom requests' do
    it do
      request = Msf::Exploit::Remote::X11::X11InternAtomRequest.new(
        name: 'Wait'
      )
      expect(request.to_binary_s).to eq(intern_atom_wait)
      expect(request.opcode).to eq(16)
      expect(request.request_length).to eq(3)
      expect(request.name).to eq('Wait')
      expect(request.only_if_exists).to eq(0)

      request = Msf::Exploit::Remote::X11::X11InternAtomRequest.new(
        name: "SERVER_OVERLAY_VISUALS\x00\x00", only_if_exists: 1
      )
      expect(request.to_binary_s).to eq(intern_atom_server_overlay_visuals)
      expect(request.opcode).to eq(16)
      expect(request.request_length).to eq(8)
      expect(request.name).to eq('SERVER_OVERLAY_VISUALS')
      expect(request.only_if_exists).to eq(1)
    end
  end
end
