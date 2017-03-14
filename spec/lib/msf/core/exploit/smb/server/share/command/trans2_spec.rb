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

  let(:unicode_path) { "\x5c\x00\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00\x65\x00\x78\x00\x65\x00\x00\x00" }
  let(:normalized_path) { '\\test.exe' }
  let(:ascii_path) { 'test.exe' }
  let(:broken_path) { 'ts.x' }
  let(:wildcard_filename) { '\\*.exe' }
  let(:wildcard_ext) { '\\test.*' }
  let(:alternate_wildcard_filename) { '\\<.exe' }

  let(:valid_find_first2) do
    "\x00\x00\x00\x64\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0b" +
    "\x00\x00\x40\xb5\x0f\x20\x00\x00\x00\x0a\x00\x00\x40\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x20\x00\x44\x00\x00\x00\x00\x00\x01" +
    "\x00\x01\x00\x23\x00\x00\x00\x00\x16\x00\x56\x05\x07\x00\x04\x01" +
    "\x00\x00\x00\x00\x5c\x00\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00" +
    "\x65\x00\x78\x00\x65\x00\x00\x00"
  end
  let(:find_first2_res_length) { 179 }
  let(:find_first2_res_data_length) { 110 }
  let(:find_first2_res_params_length) { 10 }

  let(:valid_query_file_info) do
    "\x00\x00\x00\x48\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0b" +
    "\x00\x00\xc0\xb5\x0f\x04\x00\x00\x00\x02\x00\x18\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x04\x00\x44\x00\x00\x00\x00\x00\x01" +
    "\x00\x07\x00\x07\x00\x00\x00\x00\xad\xde\xed\x03"
  end
  let(:query_file_info_res_length) { 83 }
  let(:query_file_info_res_data_length) { 22 }
  let(:query_file_info_params_length) { 2 }

  let(:valid_query_path_info) do
    "\x00\x00\x00\x5e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0b" +
    "\x00\x00\x40\xb4\x0f\x1a\x00\x00\x00\x02\x00\x28\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x44\x00\x00\x00\x00\x00\x01" +
    "\x00\x05\x00\x1d\x00\x00\x00\x00\xec\x03\x00\x00\x00\x00\x5c\x00" +
    "\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00\x65\x00\x78\x00\x65\x00" +
    "\x00\x00"
  end
  let(:query_path_info_res_length) { 101 }
  let(:query_path_info_res_data_length) { 40 }
  let(:query_path_info_params_length) { 2 }

  let(:empty_query) { "\x00\x00\x00\x00" }
  let(:empty_query_res_length) { 39 }

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
    mod.file_name = 'test.exe'
    mod.file_contents = 'metasploit'
  end

  describe "#normalize_path" do
    context "when unicode path" do
      it "returns the normalized path" do
        expect(mod.normalize_path(unicode_path)).to eq(normalized_path)
      end
    end

    context "when ascii path" do
      it "returns a broken path" do
        expect(mod.normalize_path(ascii_path)).to eq(broken_path)
      end
    end
  end

  describe "#smb_expand" do
    context "when * wildcard" do
      it "expands the filename" do
        expect(mod.smb_expand(wildcard_filename)).to eq(normalized_path)
      end

      it "doesn't expand the extension" do
        expect(mod.smb_expand(wildcard_ext)).to eq('\\test.*')
      end
    end

    context "when < wildcard" do
      it "expands the filename" do
        expect(mod.smb_expand(alternate_wildcard_filename)).to eq(normalized_path)
      end
    end
  end

  describe "#smb_cmd_trans2" do
    context "when valid FIND_FIRST2 subcommand request" do
      it "returns the number of bytes answered" do
        expect(mod.smb_cmd_trans2(msf_io, valid_find_first2)).to eq(find_first2_res_length)
      end

      it "sends a FIND_FIRST2 response with parameters" do
        mod.smb_cmd_trans2(msf_io, valid_find_first2)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload'].v['ParamCount']).to eq(find_first2_res_params_length)
      end

      it "sends a FIND_FIRST2 response with data" do
        mod.smb_cmd_trans2(msf_io, valid_find_first2)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload'].v['DataCount']).to eq(find_first2_res_data_length)
      end
    end

    context "when valid QUERY_FILE_INFO subcommand request" do
      it "returns the number of bytes answered" do
        expect(mod.smb_cmd_trans2(msf_io, valid_query_file_info)).to eq(query_file_info_res_length)
      end

      it "sends a QUERY_FILE_INFO response with parameters" do
        mod.smb_cmd_trans2(msf_io, valid_query_file_info)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload'].v['ParamCount']).to eq(query_file_info_params_length)
      end

      it "sends a QUERY_FILE_INFO response with data" do
        mod.smb_cmd_trans2(msf_io, valid_query_file_info)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload'].v['DataCount']).to eq(query_file_info_res_data_length)
      end
    end

    context "when valid QUERY_PATH_INFO subcommand request" do
      it "returns the number of bytes answered" do
        expect(mod.smb_cmd_trans2(msf_io, valid_query_path_info)).to eq(query_path_info_res_length)
      end

      it "sends a QUERY_PATH_INFO response with parameters" do
        mod.smb_cmd_trans2(msf_io, valid_query_path_info)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload'].v['ParamCount']).to eq(query_path_info_params_length)
      end

      it "sends a QUERY_PATH_INFO response with data" do
        mod.smb_cmd_trans2(msf_io, valid_query_path_info)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload'].v['DataCount']).to eq(query_path_info_res_data_length)
      end
    end

    context "when empty request" do
      it "returns the number of bytes answered" do
        expect(mod.smb_cmd_trans2(msf_io, empty_query)).to eq(empty_query_res_length)
      end

      it "sends an SMB_NT_STATUS_NOT_FOUND error to the client" do
        mod.smb_cmd_trans2(msf_io, empty_query)
        res = msf_io.read
        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload']['SMB'].v['ErrorClass']).to eq(Rex::Proto::SMB::Constants::SMB_NT_STATUS_NOT_FOUND)
      end
    end
  end
end


