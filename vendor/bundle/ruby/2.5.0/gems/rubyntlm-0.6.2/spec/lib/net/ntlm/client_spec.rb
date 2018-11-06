require 'spec_helper'

describe Net::NTLM::Client do
  let(:inst) { Net::NTLM::Client.new("test", "test01", :workstation => "testhost") }
  let(:user_session_key) {["3c4918ff0b33e2603e5d7ceaf34bb7d5"].pack("H*")}

  describe "#init_context" do

    it "returns a default Type1 message" do
      t1 = inst.init_context
      expect(t1).to be_instance_of Net::NTLM::Message::Type1
      expect(t1.domain).to eq("")
      expect(t1.workstation).to eq("testhost")
      expect(t1).to have_flag(:UNICODE)
      expect(t1).to have_flag(:OEM)
      expect(t1).to have_flag(:SIGN)
      expect(t1).to have_flag(:SEAL)
      expect(t1).to have_flag(:REQUEST_TARGET)
      expect(t1).to have_flag(:NTLM)
      expect(t1).to have_flag(:ALWAYS_SIGN)
      expect(t1).to have_flag(:NTLM2_KEY)
      expect(t1).to have_flag(:KEY128)
      expect(t1).to have_flag(:KEY_EXCHANGE)
      expect(t1).to have_flag(:KEY56)
    end

    it "clears session variable on new init_context" do
      inst.instance_variable_set :@session, "BADSESSION"
      expect(inst.session).to eq("BADSESSION")
      inst.init_context
      expect(inst.session).to be_nil
    end

    it "returns a Type1 message with custom flags" do
      flags = Net::NTLM::FLAGS[:UNICODE] | Net::NTLM::FLAGS[:REQUEST_TARGET] | Net::NTLM::FLAGS[:NTLM]
      inst = Net::NTLM::Client.new("test", "test01", :workstation => "testhost", :flags => flags)
      t1 = inst.init_context
      expect(t1).to be_instance_of Net::NTLM::Message::Type1
      expect(t1.domain).to eq("")
      expect(t1.workstation).to eq("testhost")
      expect(t1).to have_flag(:UNICODE)
      expect(t1).not_to have_flag(:OEM)
      expect(t1).not_to have_flag(:SIGN)
      expect(t1).not_to have_flag(:SEAL)
      expect(t1).to have_flag(:REQUEST_TARGET)
      expect(t1).to have_flag(:NTLM)
      expect(t1).not_to have_flag(:ALWAYS_SIGN)
      expect(t1).not_to have_flag(:NTLM2_KEY)
      expect(t1).not_to have_flag(:KEY128)
      expect(t1).not_to have_flag(:KEY_EXCHANGE)
      expect(t1).not_to have_flag(:KEY56)
    end

    it "calls authenticate! when we receive a Challenge Message" do
      t2_challenge = "TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA=="
      session = double("session")
      expect(session).to receive(:authenticate!)
      expect(Net::NTLM::Client::Session).to receive(:new).with(inst, instance_of(Net::NTLM::Message::Type2), nil).and_return(session)
      inst.init_context t2_challenge
    end

  end

end
