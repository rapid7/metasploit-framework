# -*- coding: binary -*-
require 'spec_helper'


RSpec.describe Msf::Util::WindowsCryptoHelpers do

  subject do
    context_described_class = described_class

    klass = Class.new(Msf::Post) do
      include context_described_class
    end

    klass.new
  end

  let(:boot_key_vista) do
    "\x50\xfb\xae\x5f\x5c\xd7\x70\x39\x54\xe5\x50\x48\x32\x1b\x81\x8d"
  end
  let(:boot_key_xp) do
    "\x27\x18\x0a\x2e\xe0\xfb\x98\x52\x77\x06\x24\x8e\x21\x80\xf4\x56"
  end

  # For Vista and newer
  describe "#decrypt_lsa_data" do
    let(:ciphertext) do
      # From "HKLM\\Security\\Policy\\Secrets\\"
      "\x00\x00\x00\x01\x68\x6e\x97\x93\xdb\xdb\xde\xc8\xf7\x40\x08\x79"+
      "\x9d\x91\x64\x1c\x03\x00\x00\x00\x00\x00\x00\x00\x68\x38\x3f\xc5"+
      "\x94\x10\xac\xcf\xbe\xf7\x8d\x12\xc0\xd5\xa2\x9d\x3d\x30\x30\xa8"+
      "\x6d\xbd\xc6\x48\xd3\xe4\x36\x33\x86\x91\x0d\x8d\x8f\xfc\xd4\x8a"+
      "\x87\x0c\x83\xde\xb4\x73\x9e\x21\x1b\x39\xef\x04\x36\x67\x97\x8a"+
      "\x43\x40\x79\xcf\xdb\x3d\xcc\xfe\x10\x0c\x78\x11\x00\x00\x00\x00"+
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    end
    let(:lsa_key) do
      "\x93\x19\xb7\xb3\x93\x5b\xcb\x53\x5c\xb0\x54\xce\x0f\x5e\x27\xfd"+
      "\x4f\xd1\xe3\xd3\x5b\x8c\x90\x4c\x13\xda\xb8\x39\xcc\x4e\x28\x43"
    end
    let(:plaintext) do
      # Length of actual data?
      "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"+
      # Unicode msfadmin
      "\x6d\x00\x73\x00\x66\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00"+
      # As far as I can tell, the rest of the data is gibberish?
      # Possibly random padding, since plaintext seems to always be a
      # multiple of 16 bytes.
      "\xc3\x5f\x85\xc2\x62\x55\x25\x6c\x42\x89\x88\xc1\xe0\xe8\x17\x5e"
    end

    it "should produce expected plaintext" do
      decrypted = subject.decrypt_lsa_data(ciphertext, lsa_key)
      expect(decrypted).to eq plaintext
    end
  end

  # For XP and older
  describe "#decrypt_secret_data" do
    let(:ciphertext) do
      # From "HKLM\\Security\\Policy\\Secrets\\"
      "\x22\xea\xc4\xd8\xfc\x5d\x36\xf4\x2e\x8b\xd3\x0f\x5d\xbc\xc4\x3a" +
      "\x37\x4b\x84\xea\xa0\xc0\x96\x61"
    end
    let(:boot_key) { boot_key_xp }
    let(:plaintext) do
      # Unicode "msfadmin"
      "\x6d\x00\x73\x00\x66\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00"
    end

    it "should produce expected plaintext" do
      expect(subject.decrypt_secret_data(ciphertext, boot_key)).to eq plaintext
    end

    context 'with a large secret' do
      let(:ciphertext) do
        ['d3c5991ffd49b7b072f00f3f8f1cae9d64c9300938f80ef9c0d01e1e3ec126c2127c5b27fe'\
         '2f2191a6da1b4bf0dd6aef3f04484df22babd994b18428069979de669b935b85c8d7cdb470'\
         '4e998752aedfd8a34c34ef38b8cf38f9a436d309e4c9100c46c2661652635e8cbb68990f9f'\
         'd878ae201f56979cd298b1fd0ebfe893f6f9a3e174ba3daf07e97967d5561ce3041815d523'\
         '2889ae6a17a600b2660aea0371e0e5bd6495772acec7b3954652a0172f72a0e5c8e2d5899b'\
         '12132ade0a2f5ac47c0ffd957d51769247673943200ac9652c2f68e7b71c4a5b338cd62462'\
         'd6384a502b15cb5e02dbbbf53b18f3ddc2bb7317c65422b067f27073d2fbb6ae98c8d75d44'\
         'dda34cd2b9e429fe58a75771c7fe8b9c73c3a88a1b00d80af28d644e8e1a760280b9a5cd71'\
         '319c1bfbf5ad04e9869d17ec392b0f00e7fac04affbf0825080df833d533f75e126af7c073'\
         '893ad1c3fe09af99b935b7ac8500b10f2c8383cfc30201aed4b721d71b080816739b42a0ae'\
         '0a167caf6f67ac8500b10f2c8383cfc30201aed4b721'].pack('H*')
      end
      let(:lsa_key) { ['5cd51b7d70c1814f0b37ada38babcd06'].pack('H*') }
      let(:plaintext) do
        ['5253413248000000000200003f00000001000100e7bbffa5f31998062c6cbab92863d2b9cf'\
         '0dd3a323d0dd2506ecf46febf44b517ba7475f8e470bfee47343c5eda72b039318ff76fede'\
         '3b593d758f09d96d53c900000000000000007f0c0af6c84c675435170e3ba03122610ae55c'\
         'd5f0d11dc19ca025af5680bef80000000099bcaf52b6aaa97bca0d1aa295011ce5bb372a8c'\
         '31fd4adcf93758a8e6d432cf0000000097521ad69479c5cf129b8ee43c5b98f85a1b47b40e'\
         'a06415026af9843067d18d00000000999201ae1bdbfd187d924430e9d8e7cbd306b65c49fd'\
         '805609244ae33de2785c00000000a5139bbb9733b1a6395bdf4c233e0d653a9c0526d4007b'\
         '4f54330b50ca41f861000000003160edfc16a22a6a0201f30f9a850db2272f6688bb849763'\
         'cbc61ec39cf4566b77da7989000ff520a7a4bb94f88edf52a9d3b32f8edc5fd3ea238cacef'\
         '60d21200000000000000000000000000000000000000000000000000000000000000000000'\
         '00000000000000000000'].pack('H*')
      end
      it "should produce expected plaintext" do
        expect(subject.decrypt_secret_data(ciphertext, lsa_key)).to eq plaintext
      end
    end
  end

end
