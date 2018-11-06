require 'spec_helper'

describe Net::NTLM::Message::Type1 do
  fields = [
      { :name => :sign, :class => Net::NTLM::String, :value => Net::NTLM::SSP_SIGN, :active => true },
      { :name => :type, :class => Net::NTLM::Int32LE, :value => 1, :active => true },
      { :name => :flag, :class => Net::NTLM::Int32LE, :value =>  Net::NTLM::DEFAULT_FLAGS[:TYPE1], :active => true },
      { :name => :domain, :class => Net::NTLM::SecurityBuffer, :value => '', :active => true },
      { :name => :workstation, :class => Net::NTLM::SecurityBuffer, :value =>  Socket.gethostname, :active => true },
      { :name => :os_version, :class => Net::NTLM::String, :value => '', :active => false },
  ]
  flags = [
      :UNICODE,
      :OEM,
      :REQUEST_TARGET,
      :NTLM,
      :ALWAYS_SIGN,
      :NTLM2_KEY
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

  let(:type1_packet) {"TlRMTVNTUAABAAAAB4IIAAAAAAAgAAAAAAAAACAAAAA="}

  it 'should deserialize' do
    t1 =  Net::NTLM::Message.decode64(type1_packet)
    expect(t1.class).to eq(Net::NTLM::Message::Type1)
    expect(t1.domain).to eq('')
    expect(t1.flag).to eq(557575)
    expect(t1.os_version).to eq('')
    expect(t1.sign).to eq("NTLMSSP\0")
    expect(t1.type).to eq(1)
    expect(t1.workstation).to eq('')
  end

  it 'should serialize' do
    t1 = Net::NTLM::Message::Type1.new
    t1.workstation = ''
    expect(t1.encode64).to eq(type1_packet)
  end

  describe '.parse' do
    subject(:message) { described_class.parse(data) }
    # http://davenport.sourceforge.net/ntlm.html#appendixC7
    context 'NTLM2 Session Response Authentication; NTLM2 Signing and Sealing Using the 128-bit NTLM2 Session Response User Session Key With Key Exchange Negotiated' do
      let(:data) do
        ['4e544c4d5353500001000000b78208e000000000000000000000000000000000'].pack('H*')
      end

      it 'should set the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end
      it 'should set the type' do
        expect(message.type).to eq(1)
      end
      it 'should set the flags' do
        expect(message.flag).to eq(0xe00882b7)
        expect(message).to have_flag(:UNICODE)
        expect(message).to have_flag(:OEM)
        expect(message).to have_flag(:REQUEST_TARGET)
        expect(message).to have_flag(:SIGN)
        expect(message).to have_flag(:SEAL)
        expect(message).to have_flag(:NTLM)
        expect(message).to have_flag(:ALWAYS_SIGN)
        expect(message).to have_flag(:NTLM2_KEY)
        expect(message).to have_flag(:KEY128)
        expect(message).to have_flag(:KEY_EXCHANGE)
        expect(message).to have_flag(:KEY56)
      end
      it 'should have empty workstation' do
        expect(message.workstation).to be_empty
      end
      it 'should have empty domain' do
        expect(message.domain).to be_empty
      end

    end

    # http://davenport.sourceforge.net/ntlm.html#appendixC9
    context 'NTLMv2 Authentication; NTLM1 Signing and Sealing Using the 40-bit NTLMv2 User Session Key' do
      let(:data) { ['4e544c4d53535000010000003782000000000000000000000000000000000000'].pack('H*') }

      it 'should set the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end
      it 'should set the type' do
        expect(message.type).to eq(1)
      end
      it 'should set the flags' do
        expect(message.flag).to eq(0x00008237)
        expect(message).to have_flag(:UNICODE)
        expect(message).to have_flag(:OEM)
        expect(message).to have_flag(:REQUEST_TARGET)
        expect(message).to have_flag(:SIGN)
        expect(message).to have_flag(:SEAL)
        expect(message).to have_flag(:NTLM)
        expect(message).to have_flag(:ALWAYS_SIGN)
      end
      it 'should have empty workstation' do
        expect(message.workstation).to be_empty
      end
      it 'should have empty domain' do
        expect(message.domain).to be_empty
      end
    end

    context 'NTLMv2 with OS version' do
      let(:data) { ['4e544c4d5353500001000000978208e2000000000000000000000000000000000602f0230000000f'].pack('H*') }

      it 'should set the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end
      it 'should set the type' do
        expect(message.type).to eq(1)
      end
      it 'should have empty workstation' do
        expect(message.workstation).to be_empty
      end
      it 'should have empty domain' do
        expect(message.domain).to be_empty
      end

      it 'should set OS version info' do
        expect(message.os_version).to eq(['0602f0230000000f'].pack('H*'))
      end

    end

  end

end
