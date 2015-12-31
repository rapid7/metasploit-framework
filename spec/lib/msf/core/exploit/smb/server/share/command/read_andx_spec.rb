# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/exploit/smb/server/share'
require 'rex/proto/smb/constants'

RSpec.describe Msf::Exploit::Remote::SMB::Server::Share do

  include_context "Msf::StringIO"

  subject(:mod) do
    mod = Msf::Exploit.new
    mod.extend described_class
    mod.send(:initialize)

    mod
  end

  let(:default_response_length) { 63 }
  let(:default_response) do
    "\x00\x00\x00\x3b\xff\x53\x4d\x42\x2e\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x0c\xff\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00" +
    "\x00\x3b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00"
  end

  let(:valid_request) do
    "\x00\x00\x00\x3b\xff\x53\x4d\x42\x2e\x00\x00\x00\x00\x18\x07\xe8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe" +
    "\x00\x00\x00\x01\x0c\xff\x00\xde\xde\xad\xde\x00\x00\x00\x00\x00" +
    "\x40\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00"
  end
  let(:valid_response) do
    "\x00\x00\x00\x45\xff\x53\x4d\x42\x2e\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x0c\xff\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00" +
    "\x40\x3b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x0a\x00\x6d" +
    "\x65\x74\x61\x73\x70\x6c\x6f\x69\x74"
  end
  let(:valid_response_length) { 73 }

  let(:invalid_offset_request) do
    "\x00\x00\x00\x3b\xff\x53\x4d\x42\x2e\x00\x00\x00\x00\x18\x07\xe8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe" +
    "\x00\x00\x00\x01\x0c\xff\x00\xde\xde\xad\xde\x00\xd0\x00\x00\x00" +
    "\x40\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00"
  end
  let(:empty_response) do
    "\x00\x00\x00\x3b\xff\x53\x4d\x42\x2e\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x0c\xff\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00" +
    "\x40\x3b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00"
  end
  let(:empty_response_length) { 63 }

  before(:example) do
    msf_io.string = ''
    mod.instance_variable_set('@state', {
      msf_io => {
        :multiplex_id => 0x41424344,
        :process_id   => 0x45464748,
        :file_id      => 0xdead,
        :dir_id       => 0xbeef
      }
    })
    mod.lo = 0
    mod.hi = 0
    mod.share = 'test'
    mod.file_name = 'false.exe'
    mod.file_contents = 'metasploit'
  end

  describe "#send_read_andx_res" do
    it "returns the number of bytes sent" do
      expect(mod.send_read_andx_res(msf_io)).to eq(default_response_length)
    end

    it "sends a valid SMB_COM_NT_CREATE_ANDX response to the client" do
      mod.send_read_andx_res(msf_io)
      res = msf_io.read
      expect(res).to eq(default_response)
    end
  end

  describe "#smb_cmd_read_andx" do

    context "when read request for valid offset" do
      it "returns the number of bytes answered" do
        expect(mod.smb_cmd_read_andx(msf_io, valid_request)).to eq(valid_response_length)
      end

      it "sends a valid response with the contents to the client" do
        mod.smb_cmd_read_andx(msf_io, valid_request)
        res = msf_io.read
        expect(res).to eq(valid_response)
      end
    end

    context "when read request for invalid offset" do
      it "returns the number of bytes answered" do
        expect(mod.smb_cmd_read_andx(msf_io, invalid_offset_request)).to eq(empty_response_length)
      end

      it "sends an empty read response to the client" do
        mod.smb_cmd_read_andx(msf_io, invalid_offset_request)
        res = msf_io.read
        expect(res).to eq(empty_response)
      end
    end

  end

end


