# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/opc_ua/types'

RSpec.describe Rex::Proto::OpcUa::Types::OpcUaDateTime do
  # See spec/file_fixtures/opc_ua/README.md for provenance.
  let(:response) do
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'open_secure_channel_response_node_opcua.bin'))
  end

  # The CreatedAt of the ChannelSecurityToken, which is the third field of the
  # token and so begins 0x77 bytes into the message. Its position was
  # established by walking the response field by field; the walk consumes the
  # message exactly, 135 of 135 bytes.
  let(:created_at_offset) { 0x77 }
  let(:created_at_binary) { response.byteslice(created_at_offset, 8) }

  subject(:created_at) { described_class.read(created_at_binary) }

  describe 'the epoch' do
    # The offset between the two epochs is the one number here that cannot be
    # checked by inspection, and getting it wrong shifts every timestamp the
    # scanner reports by 369 years while everything still decodes. Both
    # directions are pinned against the epochs themselves.
    it 'places tick zero at 1601-01-01 UTC' do
      expect(described_class.new(0).to_time).to eq ::Time.utc(1601, 1, 1)
    end

    # Written out rather than compared against UNIX_EPOCH_TICKS, which is the
    # constant under test: comparing it to itself would pass whatever it held.
    it 'places the Unix epoch at 116444736000000000 ticks' do
      expect(described_class.from_time(::Time.utc(1970, 1, 1))).to eq 116_444_736_000_000_000
    end

    it 'counts ten million ticks to the second' do
      expect(described_class.new(described_class::UNIX_EPOCH_TICKS + 10_000_000).to_time)
        .to eq ::Time.utc(1970, 1, 1, 0, 0, 1)
    end
  end

  describe 'against the CreatedAt of the captured OPN response' do
    it 'occupies eight bytes' do
      expect(created_at.num_bytes).to eq 8
    end

    it 'decodes the tick count' do
      expect(created_at.snapshot).to eq 134_322_644_997_030_000
    end

    # The captures were taken on 2026-08-27, which is recorded independently of
    # the bytes in spec/file_fixtures/opc_ua/README.md. A decode that landed on
    # any other date would mean the epoch or the resolution is wrong.
    it 'converts to the date the capture was taken' do
      expect(created_at.to_time).to eq ::Time.utc(2026, 8, 27, 0, 34, 59) + Rational(703, 1000)
    end

    it 'converts to a UTC time rather than a local one' do
      expect(created_at.to_time.utc?).to be true
    end

    it 're-encodes to the captured bytes' do
      expect(created_at.to_binary_s).to eq created_at_binary
    end

    # Time cannot hold a 100 nanosecond tick as a Float, so the conversion goes
    # through a Rational. This is what proves it: a round trip out to a Time and
    # back has to land on the same tick, not merely a nearby one.
    it 'round trips through a Time without losing a tick' do
      expect(described_class.from_time(created_at.to_time)).to eq created_at.snapshot
    end
  end

  describe '.now' do
    it 'returns a tick count for the current time' do
      before = described_class.from_time(::Time.now)
      now = described_class.now
      after = described_class.from_time(::Time.now)

      expect(now).to be_between(before, after)
    end
  end

  describe 'the wire format' do
    it 'is little endian' do
      expect(described_class.read("\x01\x00\x00\x00\x00\x00\x00\x00".b).snapshot).to eq 1
    end

    # DateTime is a signed Int64, so a server that sends a value below the
    # epoch is decoding to a date before 1601 rather than to a huge positive
    # number.
    it 'is signed' do
      expect(described_class.read([-1].pack('q<')).snapshot).to eq(-1)
    end
  end
end
