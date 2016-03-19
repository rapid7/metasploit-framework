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

  let(:default_find_file_both_directory_info_res_length) { 163 }
  let(:default_find_file_both_directory_info_res) do
    "\x00\x00\x00\x9f\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x0a\x0a\x00\x5e\x00\x00\x00\x0a\x00\x37\x00\x00" +
    "\x00\x5e\x00\x41\x00\x00\x00\x00\x00\x68\x00\xfd\xff\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x5e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00"
  end

  let(:default_find_file_names_info_res_length) { 81 }
  let(:default_find_file_names_info_res) do
    "\x00\x00\x00\x4d\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x0a\x0a\x00\x0c\x00\x00\x00\x0a\x00\x37\x00\x00" +
    "\x00\x0c\x00\x41\x00\x00\x00\x00\x00\x16\x00\xfd\xff\x01\x00\x01" +
    "\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00"
  end

  let(:default_find_full_directory_info_res_length) { 137 }
  let(:default_find_full_directory_info_res) do
    "\x00\x00\x00\x85\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x88\x01\xc8" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x47" +
    "\x00\x00\x44\x43\x0a\x0a\x00\x44\x00\x00\x00\x0a\x00\x37\x00\x00" +
    "\x00\x44\x00\x41\x00\x00\x00\x00\x00\x4e\x00\xfd\xff\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  end

  let(:non_existent_path) { 'non_existent' }
  let(:file_path) { 'test.exe' }
  let(:folder_path) { '\\' }

  let(:error_res_length) { 39 }

  let(:existent_file_file_both_dir_res_length) { 179 }
  let(:existent_folder_file_both_dir_res_length) { 165 }

  let(:existent_file_file_names_res_length) { 97 }
  let(:existent_folder_file_names_res_length) { 83 }

  let(:existent_file_file_full_res_length) { 153 }
  let(:existent_folder_file_full_res_length) { 139 }


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

  describe "#send_find_file_both_directory_info_res" do
    context "when no opts" do
      it "returns the number of bytes sent" do
        expect(mod.send_find_file_both_directory_info_res(msf_io)).to eq(default_find_file_both_directory_info_res_length)
      end

      it "sends a default TRANSACTION2 response" do
        mod.send_find_file_both_directory_info_res(msf_io)
        res = msf_io.read
        expect(res).to eq(default_find_file_both_directory_info_res)
      end
    end
  end

  describe "#send_find_file_names_info_res" do
    context "when no opts" do
      it "returns the number of bytes sent" do
        expect(mod.send_find_file_names_info_res(msf_io)).to eq(default_find_file_names_info_res_length)
      end

      it "sends a default TRANSACTION2 response" do
        mod.send_find_file_names_info_res(msf_io)
        res = msf_io.read
        expect(res).to eq(default_find_file_names_info_res)
      end
    end
  end

  describe "#send_find_full_directory_info_res" do
    context "when no opts" do
      it "returns the number of bytes sent" do
        expect(mod.send_find_full_directory_info_res(msf_io)).to eq(default_find_full_directory_info_res_length)
      end

      it "sends a default TRANSACTION2 response" do
        mod.send_find_full_directory_info_res(msf_io)
        res = msf_io.read
        expect(res).to eq(default_find_full_directory_info_res)
      end
    end
  end

  describe "#smb_cmd_find_file_both_directory_info" do
    context "when non existent path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_both_directory_info(msf_io, non_existent_path)).to eq(error_res_length)
      end

      it "sends a TRANSACTION2 response with SMB_STATUS_NO_SUCH_FILE error to the client" do
        mod.smb_cmd_find_file_both_directory_info(msf_io, non_existent_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload']['SMB'].v['ErrorClass']).to eq(Rex::Proto::SMB::Constants::SMB_STATUS_NO_SUCH_FILE)
      end
    end

    context "when existent file path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_both_directory_info(msf_io, file_path)).to eq(existent_file_file_both_dir_res_length)
      end

      it "sends a TRANSACTION2 response with the found FileName in SMB Data" do
        mod.smb_cmd_find_file_both_directory_info(msf_io, file_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)
        param_count = trans2_res['Payload'].v['ParamCount']
        data_count = trans2_res['Payload'].v['DataCount']

        data  = trans2_res['Payload'].v['SetupData'][2 + param_count, data_count]
        smb_data = Rex::Proto::SMB::Constants::SMB_FIND_FILE_BOTH_DIRECTORY_INFO_HDR.make_struct
        smb_data.from_s(data)

        expect(smb_data.v['FileName']).to eq(Rex::Text.to_unicode(mod.file_name))
      end
    end

    context "when existent folder path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_both_directory_info(msf_io, folder_path)).to eq(existent_folder_file_both_dir_res_length)
      end

      it "sends a TRANSACTION2 response with the found FileName in SMB Data" do
        mod.smb_cmd_find_file_both_directory_info(msf_io, folder_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)
        param_count = trans2_res['Payload'].v['ParamCount']
        data_count = trans2_res['Payload'].v['DataCount']

        data  = trans2_res['Payload'].v['SetupData'][2 + param_count, data_count]
        smb_data = Rex::Proto::SMB::Constants::SMB_FIND_FILE_BOTH_DIRECTORY_INFO_HDR.make_struct
        smb_data.from_s(data)

        expect(smb_data.v['FileName']).to eq(Rex::Text.to_unicode(folder_path))
      end
    end
  end

  describe "#smb_cmd_find_file_names_info" do
    context "when non existent path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_names_info(msf_io, non_existent_path)).to eq(error_res_length)
      end

      it "sends a TRANSACTION2 response with SMB_STATUS_NO_SUCH_FILE error to the client" do
        mod.smb_cmd_find_file_names_info(msf_io, non_existent_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload']['SMB'].v['ErrorClass']).to eq(Rex::Proto::SMB::Constants::SMB_STATUS_NO_SUCH_FILE)
      end
    end

    context "when existent file path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_names_info(msf_io, file_path)).to eq(existent_file_file_names_res_length)
      end

      it "sends a TRANSACTION2 response with the found FileName in SMB Data" do
        mod.smb_cmd_find_file_names_info(msf_io, file_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)
        param_count = trans2_res['Payload'].v['ParamCount']
        data_count = trans2_res['Payload'].v['DataCount']

        data  = trans2_res['Payload'].v['SetupData'][2 + param_count, data_count]
        smb_data = Rex::Proto::SMB::Constants::SMB_FIND_FILE_NAMES_INFO_HDR.make_struct
        smb_data.from_s(data)

        expect(smb_data.v['FileName']).to eq(Rex::Text.to_unicode(mod.file_name))
      end
    end

    context "when existent folder path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_names_info(msf_io, folder_path)).to eq(existent_folder_file_names_res_length)
      end

      it "sends a TRANSACTION2 response with the found FileName in SMB Data" do
        mod.smb_cmd_find_file_names_info(msf_io, folder_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)
        param_count = trans2_res['Payload'].v['ParamCount']
        data_count = trans2_res['Payload'].v['DataCount']

        data  = trans2_res['Payload'].v['SetupData'][2 + param_count, data_count]
        smb_data = Rex::Proto::SMB::Constants::SMB_FIND_FILE_NAMES_INFO_HDR.make_struct
        smb_data.from_s(data)

        expect(smb_data.v['FileName']).to eq(Rex::Text.to_unicode(folder_path))
      end
    end
  end

  describe "#smb_cmd_find_file_full_directory_info" do
    context "when non existent path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_full_directory_info(msf_io, non_existent_path)).to eq(error_res_length)
      end

      it "sends a TRANSACTION2 response with SMB_STATUS_NO_SUCH_FILE error to the client" do
        mod.smb_cmd_find_file_full_directory_info(msf_io, non_existent_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)

        expect(trans2_res['Payload']['SMB'].v['ErrorClass']).to eq(Rex::Proto::SMB::Constants::SMB_STATUS_NO_SUCH_FILE)
      end
    end

    context "when existent file path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_full_directory_info(msf_io, file_path)).to eq(existent_file_file_full_res_length)
      end

      it "sends a TRANSACTION2 response with the found FileName in SMB Data" do
        mod.smb_cmd_find_file_full_directory_info(msf_io, file_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)
        param_count = trans2_res['Payload'].v['ParamCount']
        data_count = trans2_res['Payload'].v['DataCount']

        data  = trans2_res['Payload'].v['SetupData'][2 + param_count, data_count]
        smb_data = Rex::Proto::SMB::Constants::SMB_FIND_FILE_FULL_DIRECTORY_INFO_HDR.make_struct
        smb_data.from_s(data)

        expect(smb_data.v['FileName']).to eq(Rex::Text.to_unicode(mod.file_name))
      end
    end

    context "when existent folder path" do
      it "returns the number of bytes sent" do
        expect(mod.smb_cmd_find_file_full_directory_info(msf_io, folder_path)).to eq(existent_folder_file_full_res_length)
      end

      it "sends a TRANSACTION2 response with the found FileName in SMB Data" do
        mod.smb_cmd_find_file_full_directory_info(msf_io, folder_path)
        res = msf_io.read

        trans2_res = Rex::Proto::SMB::Constants::SMB_TRANS_RES_PKT.make_struct
        trans2_res.from_s(res)
        param_count = trans2_res['Payload'].v['ParamCount']
        data_count = trans2_res['Payload'].v['DataCount']

        data  = trans2_res['Payload'].v['SetupData'][2 + param_count, data_count]
        smb_data = Rex::Proto::SMB::Constants::SMB_FIND_FILE_FULL_DIRECTORY_INFO_HDR.make_struct
        smb_data.from_s(data)

        expect(smb_data.v['FileName']).to eq(Rex::Text.to_unicode(folder_path))
      end
    end
  end
end


