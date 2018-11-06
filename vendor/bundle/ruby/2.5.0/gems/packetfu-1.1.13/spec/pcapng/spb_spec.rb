# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu
  module PcapNG
    describe SPB do
      before(:each) { @spb = SPB.new }

      it 'should have correct initialization values' do
        expect(@spb).to be_a(SPB)
        expect(@spb.endian).to eq(:little)
        expect(@spb.type.to_i).to eq(PcapNG::SPB_TYPE.to_i)
        expect(@spb.orig_len.to_i).to eq(0)
        expect(@spb.block_len.to_i).to eq(SPB::MIN_SIZE)
        expect(@spb.block_len2).to eq(@spb.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '../..', 'test',
                                        'sample-spb.pcapng'))[128, 0x14c]
          expect { @spb.read str }.to_not raise_error
          expect(@spb.type.to_i).to eq(PcapNG::SPB_TYPE.to_i)
          expect(@spb.block_len.to_i).to eq(0x14c)
          expect(@spb.orig_len.to_i).to eq(0x13a)
          expect(@spb.data.size).to eq(0x13a)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '../..', 'test', 'sample-spb.pcapng')) do |f|
            f.seek(128, :CUR)
            @spb.read f
          end
          expect(@spb.type.to_i).to eq(PcapNG::SPB_TYPE.to_i)
          expect(@spb.block_len.to_i).to eq(0x14c)
          expect(@spb.orig_len.to_i).to eq(0x13a)
          expect(@spb.data.size).to eq(0x13a)
        end
      end
    end
  end
end
