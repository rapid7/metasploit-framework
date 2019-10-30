# -*- coding: binary -*-
#
require 'rex/proto/ntp/modes'

RSpec.describe "Rex::Proto::NTP mode message handling" do
  before do
    @payload = 'R7' * 7
  end

  describe Rex::Proto::NTP::NTPControl do
    before do
      @control_raw = "\x1e\x05\x12\x34\x12\x34\x12\x34\x00\x00\x00\x0e" + @payload
      @control = Rex::Proto::NTP::NTPControl.new
      @control.version = 3
      @control.response = 0
      @control.more = 0
      @control.operation = 5
      @control.sequence = 0x1234
      @control.association_id = 0x1234
      @control.status = 0x1234
      @control.payload_offset = 0
      @control.payload_size = 14
      @control.payload = @payload
    end

    it 'Generates control NTP messages correctly' do
      expect(@control_raw).to eq @control.to_binary_s
    end

    it 'Parses control NTP messages correctly' do
      parsed_raw = Rex::Proto::NTP::NTPControl.new.read(@control_raw)
      expect(@control).to eq parsed_raw
    end
  end

  describe Rex::Proto::NTP::NTPGeneric do
    before do
      @generic_raw = "\xcc\x12\x34\x56" + @payload
      @generic = Rex::Proto::NTP::NTPGeneric.new
      @generic.li = 3
      @generic.version = 1
      @generic.mode = 4
      @generic.stratum = 0x12
      @generic.poll = 0x34
      @generic.precision = 0x56
      @generic.payload = @payload
    end

    it 'Generates generic NTP messages correctly' do
      expect(@generic_raw).to eq @generic.to_binary_s
    end

    it 'Parses generic NTP messages correctly' do
      parsed_raw = Rex::Proto::NTP::NTPGeneric.new.read(@generic_raw)
      expect(@generic).to eq parsed_raw
    end
  end

  describe Rex::Proto::NTP::NTPPrivate do
    before do
      @private_raw = "\x1f\x5a\x01\x99\x00\x00\x00\x00" + @payload
      @private = Rex::Proto::NTP::NTPPrivate.new
      @private.response = 0
      @private.more = 0
      @private.version = 3
      @private.mode = 7
      @private.auth = 0
      @private.sequence = 90
      @private.implementation = 1
      @private.request_code = 153
      @private.payload = @payload
    end

    it 'Generates private NTP messages correctly' do
      expect(@private_raw).to eq @private.to_binary_s
    end

    it 'Parses private NTP messages correctly' do
      parsed_raw = Rex::Proto::NTP::NTPPrivate.new.read(@private_raw)
      expect(@private).to eq parsed_raw
    end
  end
end
