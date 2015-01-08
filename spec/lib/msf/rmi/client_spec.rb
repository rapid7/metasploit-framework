# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java/serialization'
require 'rex/proto/rmi'
require 'msf/rmi/client'

class MyStringIO < StringIO

  DEFAULT_HEADER         = "JRMI\x00\x02\x4b\x00\x00\x00\x00\x00\x00"
  MULTIPLEX_HEADER       = "JRMI\x00\x02\x4d\x00\x00\x00\x00\x00\x00"
  PROTOCOL_ACK           = "\x4e\x00\x0e\x31\x37\x32\x2e\x31\x36\x2e\x31\x35\x38\x2e\x31\x33\x32\x00\x00\x06\xea"
  PROTOCOL_NOT_SUPPORTED = "\x4f"
  DEFAULT_CALL           = "\x50\xac\xed\x00\x05"
  RETURN_DATA            =
    "\x51\xac\xed\x00\x05\x77\x0f\x01\xd2\x4f\xdf\x47\x00\x00\x01\x49" +
    "\xb5\xe4\x92\x78\x80\x15\x73\x72\x00\x12\x6a\x61\x76\x61\x2e\x72" +
    "\x6d\x69\x2e\x64\x67\x63\x2e\x4c\x65\x61\x73\x65\xb0\xb5\xe2\x66" +
    "\x0c\x4a\xdc\x34\x02\x00\x02\x4a\x00\x05\x76\x61\x6c\x75\x65\x4c" +
    "\x00\x04\x76\x6d\x69\x64\x74\x00\x13\x4c\x6a\x61\x76\x61\x2f\x72" +
    "\x6d\x69\x2f\x64\x67\x63\x2f\x56\x4d\x49\x44\x3b\x70\x78\x70\x00" +
    "\x00\x00\x00\x00\x09\x27\xc0\x73\x72\x00\x11\x6a\x61\x76\x61\x2e" +
    "\x72\x6d\x69\x2e\x64\x67\x63\x2e\x56\x4d\x49\x44\xf8\x86\x5b\xaf" +
    "\xa4\xa5\x6d\xb6\x02\x00\x02\x5b\x00\x04\x61\x64\x64\x72\x74\x00" +
    "\x02\x5b\x42\x4c\x00\x03\x75\x69\x64\x74\x00\x15\x4c\x6a\x61\x76" +
    "\x61\x2f\x72\x6d\x69\x2f\x73\x65\x72\x76\x65\x72\x2f\x55\x49\x44" +
    "\x3b\x70\x78\x70\x75\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08" +
    "\x54\xe0\x02\x00\x00\x70\x78\x70\x00\x00\x00\x08\x6b\x02\xc7\x72" +
    "\x60\x1c\xc7\x95\x73\x72\x00\x13\x6a\x61\x76\x61\x2e\x72\x6d\x69" +
    "\x2e\x73\x65\x72\x76\x65\x72\x2e\x55\x49\x44\x0f\x12\x70\x0d\xbf" +
    "\x36\x4f\x12\x02\x00\x03\x53\x00\x05\x63\x6f\x75\x6e\x74\x4a\x00" +
    "\x04\x74\x69\x6d\x65\x49\x00\x06\x75\x6e\x69\x71\x75\x65\x70\x78" +
    "\x70\x80\x01\x00\x00\x01\x49\xb5\xf8\x00\xea\xe9\x62\xc1\xc0"

  def put(data)
    case data
    when DEFAULT_HEADER
      seek(0)
      write(PROTOCOL_ACK)
      seek(0)
    when MULTIPLEX_HEADER
      seek(0)
      write(PROTOCOL_NOT_SUPPORTED)
      seek(0)
    when DEFAULT_CALL
      seek(0)
      write(RETURN_DATA)
      seek(0)
    else
      write(data)
    end
  end

  def get_once(length, timeout = 10)
    read(length)
  end
end

describe Msf::Rmi::Client do
  subject(:mod) do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Rmi::Client
    mod.send(:initialize)
    mod
  end

  let(:default_header) { "JRMI\x00\x02\x4b" }
  let(:header_opts) do
    {
      :version   => 1,
      :protocol  => Rex::Proto::Rmi::Model::MULTIPLEX_PROTOCOL
    }
  end
  let(:opts_header) { "JRMI\x00\x01\x4d" }

  let(:default_call) { "\x50\xac\xed\x00\x05" }
  let(:call_opts) do
    {
      :message_id => Rex::Proto::Rmi::Model::PING_MESSAGE
    }
  end
  let(:opts_call) { "\x52\xac\xed\x00\x05" }

  let(:io) { MyStringIO.new('', 'w+b') }

  describe "#build_header" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::OutputHeader" do
        expect(mod.build_header).to be_a(Rex::Proto::Rmi::Model::OutputHeader)
      end

      it "creates a default OutputHeader" do
        expect(mod.build_header.encode).to eq(default_header)
      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Rmi::Model::OutputHeader" do
        expect(mod.build_header(header_opts)).to be_a(Rex::Proto::Rmi::Model::OutputHeader)
      end

      it "creates a OutputHeader with data from opts" do
        expect(mod.build_header(header_opts).encode).to eq(opts_header)
      end
    end
  end

  describe "#build_call" do
    context "when no opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_call).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a default Call" do
        expect(mod.build_call.encode).to eq(default_call)
      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Rmi::Model::Call" do
        expect(mod.build_call(call_opts)).to be_a(Rex::Proto::Rmi::Model::Call)
      end

      it "creates a OutputHeader with data from opts" do
        expect(mod.build_call(call_opts).encode).to eq(opts_call)
      end
    end
  end

  describe "#send_header" do
    context "when end point returns protocol ack" do
      it "returns a Rex::Proto::Rmi::Model::ProtocolAck" do
        expect(mod.send_header(sock: io)).to be_a(Rex::Proto::Rmi::Model::ProtocolAck)
      end
    end

    context "when end point returns protocol not supported" do
      it "raises RuntimeError" do
        expect do
          mod.send_header(sock: io, protocol: Rex::Proto::Rmi::Model::MULTIPLEX_PROTOCOL)
        end.to raise_error(::RuntimeError)
      end
    end
  end

  describe "#send_call" do
    context "when end point returns a value to the call" do
      it "returns a Rex::Java::Serialization::Model::Stream" do
        expect(mod.send_call(sock: io)).to be_a(Rex::Java::Serialization::Model::Stream)
      end
    end
  end
end

