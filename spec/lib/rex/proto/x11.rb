# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::X11 do
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

  describe 'X11GetPropertyResponseHeader' do
    context '#read' do
      it do
        response = Rex::Proto::X11::X11GetPropertyResponseHeader.read(get_property_resp)
        expect(response.get_property_type).to eq(31) # \x1f\x00\x00\x00
        expect(response.sequence_number).to eq(4) # \x04\x00
        expect(response.value_length).to eq(121)
      end
    end
  end

  describe 'X11GetPropertyRequest' do
    context '#initialize' do
      it do
        header = Rex::Proto::X11::X11RequestHeader.new(opcode: 20)
        body = Rex::Proto::X11::X11GetPropertyRequestBody.new(window: 1320)
        expect(header.to_binary_s + body.to_binary_s).to eq(get_property)
      end
    end

    context '#read' do
      it do
        request = Rex::Proto::X11::X11Request.read(get_property)
        expect(request.header.opcode).to eq(20)
        expect(request.body.content_length).to eq(100_000_000)
        expect(request.body.window).to eq(1320)
      end
    end
  end

  describe 'X11CreateGraphicalContextRequest' do
    context '#initialize' do
      it do
        header = Rex::Proto::X11::X11RequestHeader.new(opcode: 55)
        body = Rex::Proto::X11::X11CreateGraphicalContextRequestBody.new(
          cid: 16777216,
          drawable: 1320,
          gc_value_mask_background: 1
        )
        expect(header.to_binary_s + body.to_binary_s).to eq(creategc)
      end
    end

    context '#read' do
      it do
        request = Rex::Proto::X11::X11Request.read(creategc)
        expect(request.header.opcode).to eq(55)
        expect(request.body.request_length).to eq(5)
        expect(request.body.cid).to eq(16777216)
        expect(request.body.drawable).to eq(1320)
        expect(request.body.gc_value_mask_background).to eq(1)
        expect(request.body.background).to eq(16777215)
      end
    end
  end

  describe 'X11GetInputFocusRequest' do
    context '#initialize' do
      it do
        header = Rex::Proto::X11::X11RequestHeader.new(opcode: 43)
        body = Rex::Proto::X11::X11GetInputFocusRequestBody.new
        expect(header.to_binary_s + body.to_binary_s).to eq(get_input_focus)
      end
    end
    context '#read' do
      it do
        request = Rex::Proto::X11::X11Request.read(get_input_focus)
        expect(request.header.opcode).to eq(43)
      end
    end
  end

  describe 'X11FreeGraphicalContextRequest' do
    context '#initialize' do
      it do
        header = Rex::Proto::X11::X11RequestHeader.new(opcode: 60)
        body = Rex::Proto::X11::X11FreeGraphicalContextRequestBody.new(
          gc: 33554432
        )
        expect(header.to_binary_s + body.to_binary_s).to eq(free_gc)
      end
    end
    context '#read' do
      it do
        request = Rex::Proto::X11::X11Request.read(free_gc)
        expect(request.header.opcode).to eq(60)
        expect(request.body.gc).to eq(33554432)
      end
    end
  end

  describe 'X11InternAtomRequest' do
    context '#initialize' do
      it do
        header = Rex::Proto::X11::X11RequestHeader.new(opcode: 16)
        body = Rex::Proto::X11::X11InternAtomRequestBody.new(
          name: 'Wait'
        )
        expect(header.to_binary_s + body.to_binary_s).to eq(intern_atom_wait)
        expect(header.opcode).to eq(16)
        expect(body.request_length).to eq(3)
        expect(body.name).to eq('Wait')
        expect(body.only_if_exists).to eq(0)

        header = Rex::Proto::X11::X11RequestHeader.new(opcode: 16)
        body = Rex::Proto::X11::X11InternAtomRequestBody.new(
          name: "SERVER_OVERLAY_VISUALS\x00\x00", only_if_exists: 1
        )
        expect(header.to_binary_s + body.to_binary_s).to eq(intern_atom_server_overlay_visuals)
        expect(header.opcode).to eq(16)
        expect(body.request_length).to eq(8)
        expect(body.name).to eq('SERVER_OVERLAY_VISUALS')
        expect(body.only_if_exists).to eq(1)
      end
    end
  end
end
