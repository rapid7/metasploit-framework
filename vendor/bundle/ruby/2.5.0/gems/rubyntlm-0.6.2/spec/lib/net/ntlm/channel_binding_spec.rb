require 'spec_helper'

describe Net::NTLM::ChannelBinding do
  let(:certificates_path) { 'spec/support/certificates' }
  let(:sha_256_path) { File.join(certificates_path, 'sha_256_hash.pem') }
  let(:sha_256_cert) { OpenSSL::X509::Certificate.new(File.read(sha_256_path)) }  
  let(:cert_hash) { "\x04\x0E\x56\x28\xEC\x4A\x98\x29\x91\x70\x73\x62\x03\x7B\xB2\x3C".force_encoding(Encoding::ASCII_8BIT) }

  subject { Net::NTLM::ChannelBinding.create(sha_256_cert) }

  describe '#channel_binding_token' do

    it 'returns the correct hash' do
      expect(subject.channel_binding_token).to eq cert_hash
    end
  end
end
