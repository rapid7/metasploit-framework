# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu
  module PcapNG
    describe EPB do
      before(:each) { @epb = EPB.new }

      it 'should have correct initialization values' do
        expect(@epb).to be_a(EPB)
        expect(@epb.endian).to eq(:little)
        expect(@epb.type.to_i).to eq(PcapNG::EPB_TYPE.to_i)
        expect(@epb.interface_id.to_i).to eq(0)
        expect(@epb.tsh.to_i).to eq(0)
        expect(@epb.tsl.to_i).to eq(0)
        expect(@epb.cap_len.to_i).to eq(0)
        expect(@epb.orig_len.to_i).to eq(0)
        expect(@epb.block_len.to_i).to eq(EPB::MIN_SIZE)
        expect(@epb.block_len2).to eq(@epb.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '../..', 'test', 'sample.pcapng'))[84, 112]
          expect { @epb.read(str) }.to_not raise_error
          expect(@epb.type.to_i).to eq(PcapNG::EPB_TYPE.to_i)
          expect(@epb.block_len.to_i).to eq(112)
          expect(@epb.interface_id.to_i).to eq(0)
          expect(@epb.tsh.to_i).to eq(0x475ad)
          expect(@epb.tsl.to_i).to eq(0xd392be6a)
          expect(@epb.cap_len.to_i).to eq(78)
          expect(@epb.orig_len.to_i).to eq(@epb.cap_len.to_i)
          expect(@epb.has_options?).to be(false)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
            f.seek(84, :CUR)
            @epb.read f
          end
          expect(@epb.type.to_i).to eq(PcapNG::EPB_TYPE.to_i)
          expect(@epb.block_len.to_i).to eq(112)
          expect(@epb.interface_id.to_i).to eq(0)
          expect(@epb.tsh.to_i).to eq(0x475ad)
          expect(@epb.tsl.to_i).to eq(0xd392be6a)
          expect(@epb.cap_len.to_i).to eq(78)
          expect(@epb.orig_len.to_i).to eq(@epb.cap_len.to_i)
          expect(@epb.has_options?).to be(false)
        end

      end

      it 'should decode packet timestamp with default resolution' do
        ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
          f.seek(84, :CUR)
          @epb.read f
        end

        expect(@epb.timestamp.round).to eq(Time.utc(2009, 10, 11, 19, 29, 6))
      end

      it 'should decode packet timestamp with interface resolution' do
        ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
          f.seek(84, :CUR)
          @epb.read f
        end

        idb = IDB.new
        ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
          f.seek(52, :CUR)
          idb.read f
        end
        idb << @epb
        @epb.interface = idb

        expect(@epb.timestamp.round).to eq(Time.utc(2009, 10, 11, 19, 29, 6))
      end
    end
  end
end
