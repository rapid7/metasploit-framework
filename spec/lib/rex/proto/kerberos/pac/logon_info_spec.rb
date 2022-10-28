# -*- coding:binary -*-
require 'spec_helper'
require 'rex/proto/kerberos/pac/krb5_pac'

RSpec.describe Rex::Proto::Kerberos::Pac::Krb5ValidationInfo do

  subject(:logon_info) do
    described_class.new
  end

  let(:sample) do
    "\x01\x10\x08\x00\xcc\xcc\xcc\xcc\xa0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00" +
    "\x00\x1e\x7c\x42\xfc\x18\xd0\x01\xff\xff\xff\xff\xff\xff\xff\x7f\xff\xff\xff\xff" +
    "\xff\xff\xff\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\xff\xff\xff\xff\xff\xff\xff\x7f\x08\x00\x08\x00\x04\x00\x02\x00\x00\x00\x00\x00" +
    "\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x10\x00\x02\x00" +
    "\x00\x00\x00\x00\x14\x00\x02\x00\x00\x00\x00\x00\x18\x00\x02\x00\x00\x00\x00\x00" +
    "\xe8\x03\x00\x00\x01\x02\x00\x00\x05\x00\x00\x00\x1c\x00\x02\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x20\x00\x02\x00\x14\x00\x14\x00\x24\x00\x02\x00\x28\x00\x02\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00" +
    "\x00\x00\x00\x00\x04\x00\x00\x00\x6a\x00\x75\x00\x61\x00\x6e\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00" +
    "\x01\x02\x00\x00\x07\x00\x00\x00\x00\x02\x00\x00\x07\x00\x00\x00\x08\x02\x00\x00" +
    "\x07\x00\x00\x00\x06\x02\x00\x00\x07\x00\x00\x00\x07\x02\x00\x00\x07\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00" +
    "\x0a\x00\x00\x00\x44\x00\x45\x00\x4d\x00\x4f\x00\x2e\x00\x4c\x00\x4f\x00\x43\x00" +
    "\x41\x00\x4c\x00\x04\x00\x00\x00\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00" +
    "\x03\x99\xa8\x68\xe0\x0e\x0e\xd9\x9a\x18\xcf\xcf"
  end

  describe "#encode" do
    context "when RSA-MD5 checksum" do
      it "encodes the ServerChecksums correctly" do
        logon_info.logon_time = Time.at(1418712492)
        logon_info.effective_name = 'juan'
        logon_info.user_id = 1000
        logon_info.primary_group_id = 513
        logon_info.group_ids = [513, 512, 520, 518, 519]
        logon_info.logon_domain_name = 'DEMO.LOCAL'
        logon_info.logon_domain_id = 'S-1-5-21-1755879683-3641577184-3486455962'

        expect(logon_info.encode).to eq(sample)
      end
    end
  end

  describe "#read" do
    it "does not break" do
      BinData.trace_reading do
        x = Rex::Proto::Kerberos::Pac::Krb5ValidationInfo.read(sample)
        pp x.snapshot
        expect(x).to be_a(Rex::Proto::Kerberos::Pac::Krb5ValidationInfo)
      end
    end

    # it "does not break2" do
    #   # OG impl for logon_info
    #   # https://github.com/rapid7/metasploit-framework/blob/5f85175f56e3bf993458ebd95c7d03ba30364198/lib/rex/proto/kerberos/pac/logon_info.rb#L153-L164
    #   class RpcUnicodeStringTest < BinData::Record
    #     endian :little
    #
    #     uint16 :string_length
    #     uint16 :maximum_length
    #     uint32 :wchar_buffer_pointer # ruby_smb/dcerpc/ndr.rb
    #   end
    #   BinData.trace_reading do
    #     RpcUnicodeStringTest.read("\b\x00\b\x00\x04\x00\x02\x00")
    #
    #     RubySMB::Dcerpc::RpcUnicodeString.read("\b\x00\b\x00\x04\x00\x02\x00")
    #   end
    # end
  end

  describe "#to_binary_s" do
    it "reads and encodes the same data" do
      BinData.trace_reading do
        x = Rex::Proto::Kerberos::Pac::Krb5ValidationInfo.read(sample)

        expect(x.to_binary_s).to eq(sample)
      end
    end

    it "creating object to equal read object" do
      x = Rex::Proto::Kerberos::Pac::Krb5ValidationInfo.read(sample)

      y = Rex::Proto::Kerberos::Pac::Krb5ValidationInfo.new(
        logon_time: Time.at(1418712492),
        effective_name: 'juan',
        user_id: 1000,
        primary_group_id: 513,
        group_ids: [513, 512, 520, 518, 519],
        logon_domain_name: 'DEMO.LOCAL',
        logon_domain_id: 'S-1-5-21-1755879683-3641577184-3486455962'
      )

      # y = Rex::Proto::Kerberos::Pac::Krb5ValidationInfo.new(
      #   logon_info: logon_info
      # )

      # expect(y.logon_info).to eq(x.logon_info)

      expect(y).to eq(x)
      expect(y.to_binary_s).to eq(sample)


    end
  end
end

