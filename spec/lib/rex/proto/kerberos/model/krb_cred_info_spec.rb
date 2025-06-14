# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Model::KrbCredInfo do
  subject do
    described_class.new
  end

  let(:sample_krb_cred_info) do
    "\x30\x81\xba\xa0\x1b\x30\x19\xa0\x03\x02\x01\x17\xa1\x12\x04\x10" \
    "\x70\x74\x58\x44\x6c\x73\x44\x78\x4d\x4e\x6a\x48\x71\x65\x4a\x70" \
    "\xa1\x0a\x1b\x08\x44\x57\x2e\x4c\x4f\x43\x41\x4c\xa2\x17\x30\x15" \
    "\xa0\x03\x02\x01\x01\xa1\x0e\x30\x0c\x1b\x0a\x66\x61\x6b\x65\x5f" \
    "\x6d\x79\x73\x71\x6c\xa3\x07\x03\x05\x00\x50\xa0\x00\x00\xa5\x11" \
    "\x18\x0f\x32\x30\x32\x32\x30\x38\x30\x38\x31\x33\x30\x32\x35\x38" \
    "\x5a\xa6\x11\x18\x0f\x32\x30\x33\x32\x30\x38\x30\x35\x31\x33\x30" \
    "\x32\x35\x38\x5a\xa7\x11\x18\x0f\x32\x30\x33\x32\x30\x38\x30\x35" \
    "\x31\x33\x30\x32\x35\x38\x5a\xa8\x0a\x1b\x08\x44\x57\x2e\x4c\x4f" \
    "\x43\x41\x4c\xa9\x28\x30\x26\xa0\x03\x02\x01\x01\xa1\x1f\x30\x1d" \
    "\x1b\x08\x4d\x53\x53\x71\x6c\x53\x76\x63\x1b\x11\x64\x63\x31\x2e" \
    "\x64\x77\x2e\x6c\x6f\x63\x61\x6c\x3a\x31\x34\x33\x33"
  end

  # output from impacket which has an unused bit in the `flags` section otherwise identical
  let(:sample_krb_cred_info_impacket) do
    "\x30\x81\xba\xa0\x1b\x30\x19\xa0\x03\x02\x01\x17\xa1\x12\x04\x10" \
    "\x70\x74\x58\x44\x6c\x73\x44\x78\x4d\x4e\x6a\x48\x71\x65\x4a\x70" \
    "\xa1\x0a\x1b\x08\x44\x57\x2e\x4c\x4f\x43\x41\x4c\xa2\x17\x30\x15" \
    "\xa0\x03\x02\x01\x01\xa1\x0e\x30\x0c\x1b\x0a\x66\x61\x6b\x65\x5f" \
    "\x6d\x79\x73\x71\x6c\xa3\x07\x03\x05\x01\xa1\x40\x00\x00\xa5\x11" \
    "\x18\x0f\x32\x30\x32\x32\x30\x38\x30\x38\x31\x33\x30\x32\x35\x38" \
    "\x5a\xa6\x11\x18\x0f\x32\x30\x33\x32\x30\x38\x30\x35\x31\x33\x30" \
    "\x32\x35\x38\x5a\xa7\x11\x18\x0f\x32\x30\x33\x32\x30\x38\x30\x35" \
    "\x31\x33\x30\x32\x35\x38\x5a\xa8\x0a\x1b\x08\x44\x57\x2e\x4c\x4f" \
    "\x43\x41\x4c\xa9\x28\x30\x26\xa0\x03\x02\x01\x01\xa1\x1f\x30\x1d" \
    "\x1b\x08\x4d\x53\x53\x71\x6c\x53\x76\x63\x1b\x11\x64\x63\x31\x2e" \
    "\x64\x77\x2e\x6c\x6f\x63\x61\x6c\x3a\x31\x34\x33\x33"
  end

  let(:krb_cred_info_decoded) do
    subject.decode(sample_krb_cred_info)
  end

  let(:krb_cred_info_impacket_decoded) do
    subject.decode(sample_krb_cred_info_impacket)
  end

  describe '#decode' do
    it { expect(krb_cred_info_decoded).to be_a(Rex::Proto::Kerberos::Model::KrbCredInfo) }
    it { expect(krb_cred_info_decoded.key.value).to eq('ptXDlsDxMNjHqeJp') }
    it { expect(krb_cred_info_decoded.prealm).to eq('DW.LOCAL') }
    it { expect(krb_cred_info_decoded.pname.name_string).to include('fake_mysql') }
    it { expect(krb_cred_info_decoded.flags.value).to eq(0x50a00000) }
    it { expect(krb_cred_info_decoded.auth_time).to eq(nil) }
    it { expect(krb_cred_info_decoded.start_time).to eq('2022-08-08 13:02:58 UTC') }
    it { expect(krb_cred_info_decoded.end_time).to eq('2032-08-05 13:02:58 UTC') }
    it { expect(krb_cred_info_decoded.renew_till).to eq('2032-08-05 13:02:58 UTC') }
    it { expect(krb_cred_info_decoded.srealm).to eq('DW.LOCAL') }
    it { expect(krb_cred_info_decoded.sname.name_string).to include('MSSqlSvc', 'dc1.dw.local:1433') }

    it { expect(krb_cred_info_impacket_decoded.flags.value).to eq(0x50a00000) }

  end

  describe '#encode' do
    let(:key) do
      encryption_key = Rex::Proto::Kerberos::Model::EncryptionKey.new
      encryption_key.type = 23
      encryption_key.value = 'ptXDlsDxMNjHqeJp'
      encryption_key
    end

    let(:sname) do
      principal_name = Rex::Proto::Kerberos::Model::PrincipalName.new
      principal_name.name_type = 1
      principal_name.name_string = ['MSSqlSvc', 'dc1.dw.local:1433']
      principal_name
    end

    let(:pname) do
      principal_name = Rex::Proto::Kerberos::Model::PrincipalName.new
      principal_name.name_type = 1
      principal_name.name_string = ['fake_mysql']
      principal_name
    end

    let(:krb_cred_info) do
      subject.flags = Rex::Proto::Kerberos::Model::KdcOptionFlags.new(0x50a00000)
      subject.key = key
      subject.srealm = 'DW.LOCAL'
      subject.prealm = 'DW.LOCAL'
      subject.pname = pname
      subject.sname = sname
      subject.auth_time = nil
      subject.start_time = Time.parse('2022-08-08 13:02:58 UTC')
      subject.end_time = Time.parse('2032-08-05 13:02:58 UTC')
      subject.renew_till = Time.parse('2032-08-05 13:02:58 UTC')
      subject
    end

    it 'encodes correctly' do
      expect(krb_cred_info.encode).to eq(sample_krb_cred_info)
    end
  end
end
