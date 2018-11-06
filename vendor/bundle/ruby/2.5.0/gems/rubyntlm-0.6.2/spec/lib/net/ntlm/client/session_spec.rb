require 'spec_helper'

describe Net::NTLM::Client::Session do
  let(:t2_challenge) { Net::NTLM::Message.decode64 "TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA==" }
  let(:inst) { Net::NTLM::Client::Session.new(nil, t2_challenge) }
  let(:user_session_key) {["3c4918ff0b33e2603e5d7ceaf34bb7d5"].pack("H*")}
  let(:client_sign_key) {["f7f97a82ec390f9c903dac4f6aceb132"].pack("H*")}
  let(:client_seal_key) {["6f0d99535033951cbe499cd1914fe9ee"].pack("H*")}
  let(:server_sign_key) {["f7f97a82ec390f9c903dac4f6aceb132"].pack("H*")}
  let(:server_seal_key) {["6f0d99535033951cbe499cd1914fe9ee"].pack("H*")}

  describe "#sign_message" do

    it "signs a message and when KEY_EXCHANGE is true" do
      expect(inst).to receive(:client_sign_key).and_return(client_sign_key)
      expect(inst).to receive(:client_seal_key).and_return(client_seal_key)
      expect(inst).to receive(:negotiate_key_exchange?).and_return(true)
      sm = inst.sign_message("Test Message")
      str = "01000000b35ccd60c110c52f00000000"
      expect(sm.unpack("H*")[0]).to eq(str)
    end

  end

  describe "#verify_signature" do

    it "verifies a message signature" do
      expect(inst).to receive(:server_sign_key).and_return(server_sign_key)
      expect(inst).to receive(:server_seal_key).and_return(server_seal_key)
      expect(inst).to receive(:negotiate_key_exchange?).and_return(true)
      sig = "01000000b35ccd60c110c52f00000000"
      sm = inst.verify_signature([sig].pack("H*"), "Test Message")
      expect(sm).to be true
    end

  end

  describe "#seal_message" do
    it "should seal the message" do
      expect(inst).to receive(:client_seal_key).and_return(client_seal_key)
      emsg = inst.seal_message("rubyntlm")
      expect(emsg.unpack("H*")[0]).to eq("d7389b9604f6274f")
    end
  end

  describe "#unseal_message" do
    it "should unseal the message" do
      expect(inst).to receive(:server_seal_key).and_return(server_seal_key)
      msg = inst.unseal_message(["d7389b9604f6274f"].pack("H*"))
      expect(msg).to eq("rubyntlm")
    end
  end

  describe "#exported_session_key" do
    it "returns a random 16-byte key when negotiate_key_exchange? is true" do
      expect(inst).to receive(:negotiate_key_exchange?).and_return(true)
      expect(inst).not_to receive(:user_session_key)
      inst.exported_session_key
    end

    it "returns the user_session_key when negotiate_key_exchange? is false" do
      expect(inst).to receive(:negotiate_key_exchange?).and_return(false)
      expect(inst).to receive(:user_session_key).and_return(user_session_key)
      inst.exported_session_key
    end
  end

end
