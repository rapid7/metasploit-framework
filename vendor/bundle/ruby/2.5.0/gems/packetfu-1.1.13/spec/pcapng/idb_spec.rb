# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu
  module PcapNG
    describe IDB do
      before(:each) { @idb = IDB.new }

      it 'should have correct initialization values' do
        expect(@idb).to be_a(IDB)
        expect(@idb.endian).to eq(:little)
        expect(@idb.type.to_i).to eq(PcapNG::IDB_TYPE.to_i)
        expect(@idb.link_type.to_i).to eq(PcapNG::LINKTYPE_ETHERNET)
        expect(@idb.snaplen.to_i).to eq(0)
        expect(@idb.block_len.to_i).to eq(IDB::MIN_SIZE)
        expect(@idb.block_len2).to eq(@idb.block_len)
      end

      it 'should decode tsresol on demand from its options' do
        @idb.options.read [9, 1, 4].pack('vvC')
        expect(@idb.ts_resol).to eq(1E-4)

        @idb.options.read [9, 1, 0x83].pack('vvC')
        expect(@idb.ts_resol(true)).to eq(2**-3)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '../..', 'test', 'sample.pcapng'))[52, 32]
          expect { @idb.read(str) }.to_not raise_error
          expect(@idb.type.to_i).to eq(PcapNG::IDB_TYPE.to_i)
          expect(@idb.block_len.to_i).to eq(32)
          expect(@idb.link_type.to_i).to eq(PcapNG::LINKTYPE_ETHERNET)
          expect(@idb.snaplen.to_i).to eq(0xffff)
          expect(@idb.has_options?).to be(true)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '../..', 'test', 'sample.pcapng')) do |f|
            f.seek(52, :CUR)
            @idb.read f
          end
          expect(@idb.type.to_i).to eq(PcapNG::IDB_TYPE.to_i)
          expect(@idb.block_len.to_i).to eq(32)
          expect(@idb.link_type.to_i).to eq(PcapNG::LINKTYPE_ETHERNET)
          expect(@idb.snaplen.to_i).to eq(0xffff)
          expect(@idb.has_options?).to be(true)
        end
      end
    end
  end
end
