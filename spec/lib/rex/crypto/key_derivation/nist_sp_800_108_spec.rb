require 'spec_helper'
require 'rex/crypto/key_derivation/nist_sp_800_108'

RSpec.describe Rex::Crypto::KeyDerivation::NIST_SP_800_108 do
  describe '.counter' do
    let(:secret) { [ '000102030405060708090A0B0C0D0E0F' ].pack('H*') }
    let(:prf) { RSpec::Mocks::Double.new('prf') }
    let(:length) { 32 }
    let(:label) { "RSpec Test Label\0" }
    let(:context) { "RSpec Test Context\0" }

    it 'builds the context block correctly for the prf' do
      info = [ 1 ].pack('L>') + label + "\x00".b + context + [ length * 8 ].pack('L>')
      expect(prf).to receive(:call).with(info).and_return(OpenSSL::HMAC.digest('SHA256', secret, info))
      described_class.counter(length, prf, label: label, context: context)
    end
  end

  describe '.counter_hmac' do
    let(:secret) { [ '000102030405060708090A0B0C0D0E0F' ].pack('H*') }
    let(:length) { 32 }
    let(:label) { "RSpec Test Label\0" }
    let(:context) { "RSpec Test Context\0" }

    context 'when the algorithm is invalid' do
      let(:algorithm) { 'InvalidAlgorithm' }

      it 'raises an error' do
        expect { described_class.counter_hmac(secret, length, algorithm, label: label, context: context) }.to raise_error(RuntimeError, /digest algorithm/)
      end
    end

    context 'when the algorithm is SHA256' do
      let(:algorithm) { 'SHA256' }
      before(:each) { expect(OpenSSL::HMAC).to receive(:digest).at_least(:once).with(algorithm, secret, anything).and_call_original }
      before(:each) { expect(described_class).to receive(:counter).with(length, anything, context: context, label: label, keys: instance_of(Integer)).and_call_original }

      it 'uses SHA256 to calculate 1 key' do
        keys = described_class.counter_hmac(secret, length, algorithm, label: label, context: context)
        expect(keys.length).to eq 1
        expect(keys[0]).to eq ['5889a9fe18d9d51b5eb95272088acbe38bd2ea82517f1956b919dc549a945aa0'].pack('H*')
      end

      it 'uses SHA256 to calculate 2 keys' do
        keys = described_class.counter_hmac(secret, length, algorithm, label: label, context: context, keys: 2)
        expect(keys.length).to eq 2
        expect(keys[0]).to eq ['2060ea190b9ac147ccfbe2c094c49be04dcac80db6d05b1c32c54529caf24d43'].pack('H*')
        expect(keys[1]).to eq ['f66a460fc1d03451c1ef669ee10953815460d368668be13301d6314878ed771d'].pack('H*')
      end
    end
  end
end