# encoding: UTF-8
require 'spec_helper'

describe Net::NTLM::Message::Type2 do

  fields = [
      { :name => :sign, :class => Net::NTLM::String, :value => Net::NTLM::SSP_SIGN, :active => true },
      { :name => :type, :class => Net::NTLM::Int32LE, :value => 2, :active => true },
      { :name => :challenge, :class => Net::NTLM::Int64LE, :value => 0, :active => true },
      { :name => :context, :class => Net::NTLM::Int64LE, :value => 0, :active => false },
      { :name => :flag, :class => Net::NTLM::Int32LE, :value =>  Net::NTLM::DEFAULT_FLAGS[:TYPE2], :active => true },
      { :name => :target_name, :class => Net::NTLM::SecurityBuffer, :value => '', :active => true },
      { :name => :target_info, :class => Net::NTLM::SecurityBuffer, :value =>  '', :active => false },
      { :name => :os_version, :class => Net::NTLM::String, :value => '', :active => false },
  ]
  flags = [
      :UNICODE
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

  let(:type2_packet) {"TlRMTVNTUAACAAAAHAAcADgAAAAFgooCJ+UA1//+ZM4AAAAAAAAAAJAAkABUAAAABgGxHQAAAA9WAEEARwBSAEEATgBUAC0AMgAwADAAOABSADIAAgAcAFYAQQBHAFIAQQBOAFQALQAyADAAMAA4AFIAMgABABwAVgBBAEcAUgBBAE4AVAAtADIAMAAwADgAUgAyAAQAHAB2AGEAZwByAGEAbgB0AC0AMgAwADAAOABSADIAAwAcAHYAYQBnAHIAYQBuAHQALQAyADAAMAA4AFIAMgAHAAgAZBMdFHQnzgEAAAAA"}
  let(:type3_packet) {"TlRMTVNTUAADAAAAGAAYAEQAAADAAMAAXAAAAAAAAAAcAQAADgAOABwBAAAUABQAKgEAAAAAAAA+AQAABYKKAgAAAADVS27TfQGmWxSSbXmolTUQyxJmD8ISQuBKKHFKC8GksUZISYc8Ps9RAQEAAAAAAAAANasTdCfOAcsSZg/CEkLgAAAAAAIAHABWAEEARwBSAEEATgBUAC0AMgAwADAAOABSADIAAQAcAFYAQQBHAFIAQQBOAFQALQAyADAAMAA4AFIAMgAEABwAdgBhAGcAcgBhAG4AdAAtADIAMAAwADgAUgAyAAMAHAB2AGEAZwByAGEAbgB0AC0AMgAwADAAOABSADIABwAIAGQTHRR0J84BAAAAAAAAAAB2AGEAZwByAGEAbgB0AGsAbwBiAGUALgBsAG8AYwBhAGwA"}

  it 'should deserialize' do
    t2 =  Net::NTLM::Message.decode64(type2_packet)
    expect(t2.class).to eq(Net::NTLM::Message::Type2)
    expect(t2.challenge).to eq(14872292244261496103)
    expect(t2.context).to eq(0)
    expect(t2.flag).to eq(42631685)
    expect(t2.os_version).to eq(['0601b11d0000000f'].pack('H*'))
    expect(t2.sign).to eq("NTLMSSP\0")

    t2_target_info = Net::NTLM::EncodeUtil.decode_utf16le(t2.target_info)
    if RUBY_VERSION == "1.8.7"
      expect(t2_target_info).to eq("\x02\x1CVAGRANT-2008R2\x01\x1CVAGRANT-2008R2\x04\x1Cvagrant-2008R2\x03\x1Cvagrant-2008R2\a\b\e$(D+&\e(B\0\0")
    else
      expect(t2_target_info).to eq("\u0002\u001CVAGRANT-2008R2\u0001\u001CVAGRANT-2008R2\u0004\u001Cvagrant-2008R2\u0003\u001Cvagrant-2008R2\a\b፤ᐝ❴ǎ\0\0")
    end

    expect(Net::NTLM::EncodeUtil.decode_utf16le(t2.target_name)).to eq("VAGRANT-2008R2")
    expect(t2.type).to eq(2)
  end

  it 'should serialize' do
    source = Net::NTLM::Message.decode64(type2_packet)

    t2 =  Net::NTLM::Message::Type2.new
    t2.challenge = source.challenge
    t2.context = source.context
    t2.flag = source.flag
    t2.os_version = source.os_version
    t2.sign = source.sign
    t2.target_info = source.target_info
    t2.target_name = source.target_name
    t2.type = source.type
    t2.enable(:context)
    t2.enable(:target_info)
    t2.enable(:os_version)

    expect(t2.encode64).to eq(type2_packet)
  end

  it 'should generate a type 3 response' do
    t2 = Net::NTLM::Message.decode64(type2_packet)

    type3_known = Net::NTLM::Message.decode64(type3_packet)
    type3_known.flag = 0x028a8205
    type3_known.enable(:session_key)
    type3_known.enable(:flag)

    t3 = t2.response({:user => 'vagrant', :password => 'vagrant', :domain => ''}, {:ntlmv2 => true, :workstation => 'kobe.local'})
    expect(t3.domain).to eq(type3_known.domain)
    expect(t3.flag).to eq(type3_known.flag)
    expect(t3.sign).to eq("NTLMSSP\0")
    expect(t3.workstation).to eq("k\0o\0b\0e\0.\0l\0o\0c\0a\0l\0")
    expect(t3.user).to eq("v\0a\0g\0r\0a\0n\0t\0")
    expect(t3.session_key).to eq('')
  end

  it 'should upcase domain when provided' do
    t2 = Net::NTLM::Message.decode64(type2_packet)
    t3 = t2.response({:user => 'vagrant', :password => 'vagrant', :domain => 'domain'}, {:ntlmv2 => true, :workstation => 'kobe.local'})
    expect(t3.domain).to eq("D\0O\0M\0A\0I\0N\0")
  end

  describe '.parse' do
    subject(:message) { described_class.parse(data) }
    # http://davenport.sourceforge.net/ntlm.html#appendixC7
    context 'NTLM2 Session Response Authentication; NTLM2 Signing and Sealing Using the 128-bit NTLM2 Session Response User Session Key With Key Exchange Negotiated' do
      let(:data) do
        [
          '4e544c4d53535000020000000c000c0030000000358289e0677f1c557a5ee96c' \
          '0000000000000000460046003c00000054004500530054004e00540002000c00' \
          '54004500530054004e00540001000c004d0045004d0042004500520003001e00' \
          '6d0065006d006200650072002e0074006500730074002e0063006f006d000000' \
          '0000'
        ].pack('H*')
      end

      it 'should set the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end
      it 'should set the type' do
        expect(message.type).to eq(2)
      end
      it 'should set the target name' do
        # TESTNT
        expect(message.target_name).to eq(["54004500530054004e005400"].pack('H*'))
      end
      it 'should set the flags' do
        expect(message.flag).to eq(0xe0898235)
      end
      it 'should set the challenge' do
        expect(message.challenge).to eq(0x6ce95e7a551c7f67)
      end
      it 'should set an empty context' do
        expect(message.context).to be_zero
      end
      it 'should set target info' do
        ti = [
          '02000c0054004500530054004e00540001000c004d0045004d00420045005200' \
          '03001e006d0065006d006200650072002e0074006500730074002e0063006f00' \
          '6d0000000000'
        ].pack('H*')
        expect(message.target_info).to eq(ti)
      end

    end
  end

end
