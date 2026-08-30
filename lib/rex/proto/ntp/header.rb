# -*- coding: binary -*-

require 'bindata'
require 'bigdecimal'
require 'bigdecimal/util'

module Rex
module Proto
module NTP::Header

  class NTPShort < BinData::Primitive
    # see: https://datatracker.ietf.org/doc/html/rfc5905#section-6
    endian :big

    uint16  :seconds
    uint16  :fraction

    def set(value)
      value = value.to_d
      seconds = value.floor
      self.seconds = seconds
      self.fraction = ((value - seconds) * BigDecimal(2**16)).round
    end

    def get
      BigDecimal(seconds.value) + (BigDecimal(fraction.value) / BigDecimal(2**16))
    end
  end

  class NTPTimestamp < BinData::Primitive
    UNIX_EPOCH = Time.utc(1900, 1, 1)
    # see: https://datatracker.ietf.org/doc/html/rfc5905#section-6
    endian :big

    uint32 :seconds
    uint32 :fraction

    def get
      return nil if seconds == 0 && fraction == 0

      time_in_seconds = seconds + BigDecimal(fraction.to_s) / BigDecimal((2**32).to_s)
      (UNIX_EPOCH + time_in_seconds).utc
    end

    def set(time)
      if time.nil?
        seconds = fraction = 0
      else
        seconds_since_epoch = time.to_r - UNIX_EPOCH.to_r
        seconds = seconds_since_epoch.to_i
        fraction = ((seconds_since_epoch - seconds) * (2**32)).to_i
      end

      self.seconds = seconds
      self.fraction = fraction
    end
  end

  class NTPExtension < BinData::Record
    endian :big

    uint16      :ext_type
    uint16      :ext_length
    uint8_array :ext_value, initial_length: :ext_length
  end

  # A unified structure capable of representing NTP versions 1-4
  class NTPHeader < BinData::Record
    # see: https://datatracker.ietf.org/doc/html/rfc958 (NTP v0 - unsupported)
    # see: https://datatracker.ietf.org/doc/html/rfc1059 (NTP v1)
    # see: https://datatracker.ietf.org/doc/html/rfc1119 (NTP v2)
    # see: https://datatracker.ietf.org/doc/html/rfc1305 (NTP v3)
    # see: https://datatracker.ietf.org/doc/html/rfc5905 (NTP v4)
    endian :big
    hide :bytes_remaining_0, :bytes_remaining_1

    bit2                  :leap_indicator
    bit3                  :version_number, initial_value: 4, assert: -> { version_number.between?(1, 4) }
    bit3                  :mode, onlyif: -> { version_number > 1 }
    resume_byte_alignment
    uint8                 :stratum
    int8                  :poll
    int8                  :precision
    ntp_short             :root_delay
    ntp_short             :root_dispersion
    string                :reference_id, length: 4, trim_padding: true
    ntp_timestamp         :reference_timestamp
    ntp_timestamp         :origin_timestamp
    ntp_timestamp         :receive_timestamp
    ntp_timestamp         :transmit_timestamp
    count_bytes_remaining :bytes_remaining_0
    buffer :extensions, length: -> { bytes_remaining_0 - 20 }, onlyif: :has_extensions? do
      array :extensions, type: :ntp_extension, read_until: :eof
    end
    count_bytes_remaining :bytes_remaining_1
    uint32                :key_identifier, onlyif: :has_key_identifier?
    uint8_array           :message_digest, initial_length: OpenSSL::Digest::MD5.new.digest_length, onlyif: :has_message_digest?

    private

    def has_extensions?
      # -20 for the length of the key identifier and message digest which are required when extensions are present
      bytes_remaining_0 - 20 > 0 && version_number > 3
    end

    def has_key_identifier?
      bytes_remaining_1 > 0 || !key_identifier.clear?
    end

    def has_message_digest?
      bytes_remaining_1 > 4 || !message_digest.clear?
    end
  end

end
end
end
