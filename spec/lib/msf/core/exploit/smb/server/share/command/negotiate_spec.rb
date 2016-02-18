
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

  let(:default_response_length) { 73 }
  let(:default_response) do
    "\x00\x00\x00\x45\xff\x53\x4d\x42" +
    "\x72\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x11\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00"
  end
  let(:valid_request) do
    "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x43\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe" +
    "\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f" +
    "\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02" +
    "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f" +
    "\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70" +
    "\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30" +
    "\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54" +
    "\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
  end
  let(:valid_response_length) { 81 }
  let(:challenge_length) { 8 }

  before(:example) do
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
  end

  describe "#send_negotitate_res" do
    it "returns the number of bytes sent" do
      expect(mod.send_negotitate_res(msf_io)).to eq(default_response_length)
    end

    it "sends a valid SMB_COM_NEGOTIATE response to the client" do
      mod.send_negotitate_res(msf_io)
      res = msf_io.read
      expect(res).to eq(default_response)
    end
  end

  describe "#smb_cmd_negotiate" do
    it "returns the number of bytes answered" do
      expect(mod.smb_cmd_negotiate(msf_io, valid_request)).to eq(valid_response_length)
    end

    it "returns an 8 byte challenge" do
      mod.smb_cmd_negotiate(msf_io, valid_request)
      pkt = Rex::Proto::SMB::Constants::SMB_NEG_RES_NT_PKT.make_struct
      pkt.from_s(msf_io.read)

      expect(pkt['Payload'].v['KeyLength']).to eq(challenge_length)
    end
  end

end


