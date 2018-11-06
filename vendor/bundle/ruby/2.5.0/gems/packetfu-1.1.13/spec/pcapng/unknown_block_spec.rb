# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu
  module PcapNG
    describe UnknownBlock do
      before(:each) { @ub = UnknownBlock.new }

      it 'should have correct initialization values' do
        expect(@ub).to be_a(UnknownBlock)
        expect(@ub.endian).to eq(:little)
        expect(@ub.type.to_i).to eq(0)
        expect(@ub.block_len.to_i).to eq(UnknownBlock::MIN_SIZE)
        expect(@ub.block_len2).to eq(@ub.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = "\xff\xff\xff\xff\x0c\x00\x00\x00\x0c\x00\x00\x00"
          expect { @ub.read(str) }.to_not raise_error
          expect(@ub.type.to_i).to eq(0xffffffff)
          expect(@ub.block_len.to_i).to eq(12)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
            @ub.read(f)
          end
          expect(@ub.type.to_i).to eq(0x0a0d0d0a)
          expect(@ub.block_len.to_i).to eq(52)
        end
      end
    end
  end
end
