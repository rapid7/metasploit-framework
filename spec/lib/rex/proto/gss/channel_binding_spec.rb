# -*- coding:binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Gss::ChannelBinding do
  let(:peer_cert) do
    OpenSSL::X509::Certificate.new(<<~CERTIFICATE
      -----BEGIN CERTIFICATE-----
      MIIGijCCBXKgAwIBAgITNQAAAAKLvdEO5Pbo1AAAAAAAAjANBgkqhkiG9w0BAQsF
      ADBcMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxHTAbBgoJkiaJk/IsZAEZFg1sYWJz
      MWNvbGxhYnUwMSQwIgYDVQQDExtsYWJzMWNvbGxhYnUwLVNSVi1BRERTMDEtQ0Ew
      HhcNMjQwNDE5MTcyMzAwWhcNMjUwNDE5MTcyMzAwWjApMScwJQYDVQQDEx5TUlYt
      QUREUzAxLmxhYnMxY29sbGFidTAubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IB
      DwAwggEKAoIBAQCr/zrK2bEDVkBewjWznxhH9gW6HQ+1cC/gx8lOVF8mju/hTmTQ
      J4lMvGyub3yUG0K5vt17veGf3fTaGBT9tn3yQf1IBMF71hiswQCZ0KV2Hti4Zd1b
      eWmw0UPF1xtpRHznAIjmKDHLvXjzEHnw/DNxPMbSI9Xu7x2iy6tGumh1neb4ojcK
      q8Fni0q3HT9WqybsD1cMchzNWgz+KPiimjusCujLGu+aGJdr5vMpg2Ho9GSt4OaT
      8/g6+XUFWcD6xi7lcoNlb1WYGexWZ0TZFzO36g/7FWsy+1E79/8XbyOTeePk3PHV
      QK/xS8nrYoCjgHOp+6gNaEGcXrUsoMt/yqaxAgMBAAGjggN2MIIDcjAvBgkrBgEE
      AYI3FAIEIh4gAEQAbwBtAGEAaQBuAEMAbwBuAHQAcgBvAGwAbABlAHIwHQYDVR0l
      BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDB4BgkqhkiG
      9w0BCQ8EazBpMA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwCwYJYIZI
      AWUDBAEqMAsGCWCGSAFlAwQBLTALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEFMAcG
      BSsOAwIHMAoGCCqGSIb3DQMHMB0GA1UdDgQWBBS/lN4BjRJ+SlqTLHhQXUsYwCbv
      7zAfBgNVHSMEGDAWgBRXm1vGVJecz1AoeScpiNfSfSGr6zCB5AYDVR0fBIHcMIHZ
      MIHWoIHToIHQhoHNbGRhcDovLy9DTj1sYWJzMWNvbGxhYnUwLVNSVi1BRERTMDEt
      Q0EsQ049U1JWLUFERFMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
      ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1sYWJzMWNvbGxhYnUw
      LERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
      bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB1QYIKwYBBQUHAQEEgcgwgcUwgcIG
      CCsGAQUFBzAChoG1bGRhcDovLy9DTj1sYWJzMWNvbGxhYnUwLVNSVi1BRERTMDEt
      Q0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2Vz
      LENOPUNvbmZpZ3VyYXRpb24sREM9bGFiczFjb2xsYWJ1MCxEQz1sb2NhbD9jQUNl
      cnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0
      eTBKBgNVHREEQzBBoB8GCSsGAQQBgjcZAaASBBBXIgqBkBcAQIVerWGi3mV5gh5T
      UlYtQUREUzAxLmxhYnMxY29sbGFidTAubG9jYWwwSwYJKwYBBAGCNxkCBD4wPKA6
      BgorBgEEAYI3GQIBoCwEKlMtMS01LTIxLTc5NTUwMy0zMDUwMzM0Mzk0LTM2NDQ0
      MDA2MjQtMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAw/1kFOsPbYc1J0JWPqfnhKmO
      TCim8r4pIckZZpkgLXjAzfHdJLYt9O5s7I48lojqdeg61EpjVxj1h1BT3aTDk+TS
      hW3WlvpscOKdu4+tqpJ96Buf6Y91QWDyKn7ZRM9Mq3GbTqkEFMLczGAqBWuqUDHG
      Lo7tyBfLw5mMAKV7xFHPjH5nQ0tzfymp+yuP5TKCzTf7v06621PPZ1xVeZTQxAmx
      e9ViEMYy5IC+okMsIXg6+wbynubxL6CzZFZhwJtujmRfHABuydV17El2NrUW1pdQ
      cFUXmAXwiCvGBSkr7QfsMGx70pmP+VBQKkBRWaCo00Vj0ukRFV5r/BtKbZp0+w==
      -----END CERTIFICATE-----
    CERTIFICATE
    )
  end

  describe '.create' do
    let(:channel_binding) { described_class.create(peer_cert) }

    # this ensures API compatibility with the underlying Net::NTLM::ChannelBinding class which would use the certificate
    # directly however that couples the calculation logic with the object type
    it 'should DER encode the certificate' do
      der_encoded = peer_cert.to_der
      expect(peer_cert).to receive(:to_der).with(no_args).and_return(der_encoded).exactly(1).times
      expect(described_class).to receive(:new).with(der_encoded).exactly(1).times
      described_class.create(peer_cert)
    end

    describe '#channel' do
      it 'should be the DER encoded certificate data' do
        expect(channel_binding.channel).to eq peer_cert.to_der
      end
    end

    describe '#channel_hash' do
      let(:channel_hash) { channel_binding.channel_hash }
      it 'should be an OpenSSL::Digest' do
        expect(channel_hash).to be_a OpenSSL::Digest
      end

      it 'should be correct' do
        expect(channel_hash.digest.unpack1('H*')).to eq 'f79b1e5d605710356244f2d5005c1b57895c88dcfbbae22a15349b192ddca597'
      end
    end

    describe '#digest_algorithm' do
      it 'should be SHA256' do
        expect(channel_binding.digest_algorithm).to eq 'SHA256'
      end
    end

    describe '#unique_prefix' do
      it 'should be "tls-server-end-point"' do
        expect(channel_binding.unique_prefix).to eq 'tls-server-end-point'
      end
    end
  end

  describe '.from_tls_cert' do
    let(:channel_binding) { described_class.from_tls_cert(peer_cert) }

    it 'should check the signature algorithm' do
      expect(peer_cert).to receive(:signature_algorithm).with(no_args).and_call_original.at_least(1).times
      described_class.from_tls_cert(peer_cert)
    end

    describe '#channel' do
      it 'should be the DER encoded certificate data' do
        expect(channel_binding.channel).to eq peer_cert.to_der
      end
    end

    describe '#channel_hash' do
      let(:channel_hash) { channel_binding.channel_hash }
      it 'should be an OpenSSL::Digest' do
        expect(channel_hash).to be_a OpenSSL::Digest
      end

      it 'should be correct' do
        expect(channel_hash.digest.unpack1('H*')).to eq 'f79b1e5d605710356244f2d5005c1b57895c88dcfbbae22a15349b192ddca597'
      end
    end

    describe '#digest_algorithm' do
      it 'should be SHA256' do
        expect(channel_binding.digest_algorithm).to eq 'SHA256'
      end
    end

    describe '#unique_prefix' do
      it 'should be "tls-server-end-point"' do
        expect(channel_binding.unique_prefix).to eq 'tls-server-end-point'
      end
    end
  end
end
