# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu
  module PcapNG
    describe SHB do
      before(:each) { @shb = SHB.new }

      it 'should have correct initialization values' do
        expect(@shb).to be_a(SHB)
        expect(@shb.endian).to eq(:little)
        expect(@shb.type.to_i).to eq(PcapNG::SHB_TYPE.to_i)
        expect(@shb.block_len.to_i).to eq(SHB::MIN_SIZE)
        expect(@shb.magic.to_s).to eq(SHB::MAGIC_LITTLE)
        expect(@shb.ver_major.to_i).to eq(1)
        expect(@shb.ver_minor.to_i).to eq(0)
        expect(@shb.section_len.to_i).to eq(0xffffffff_ffffffff)
        expect(@shb.block_len2).to eq(@shb.block_len)
        expect(@shb.interfaces).to eq([])
        expect(@shb.unknown_blocks).to eq([])
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '../..', 'test', 'sample.pcapng'), 52)
          expect { @shb.read(str) }.to_not raise_error
          expect(@shb.block_len.to_i).to eq(52)
          expect(@shb.has_options?).to be(true)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
            @shb.read(f)
          end
          expect(@shb.block_len.to_i).to eq(52)
          expect(@shb.has_options?).to be(true)
        end
      end
    end
  end
end
