# encoding: ASCII-8BIT

module Dnsruby
  class RR
    # Class for Geographic Position (GPOS) resource records.
    #
    # RFC 1712 (https://www.ietf.org/rfc/rfc1712.txt)
    class GPOS < RR

      TypeValue = Types::GPOS
      ClassValue = Classes::IN
      ClassHash[[TypeValue, ClassValue]] = self  #:nodoc: all

      attr_accessor :longitude, :latitude, :altitude  # NOTE: these are strings, not numbers

      REQUIRED_KEYS = [:longitude, :latitude, :altitude]


      # As with all resource record subclasses of RR, this class cannot be
      # directly instantiated, but instead must be instantiated via use of
      # one of the RR class methods.  These GPOS class methods are wrappers
      # around those RR methods, so that there is an interface on the GPOS
      # class for creating GPOS instances.

      # Create an instance from a hash of parameters, e.g.:
      #  {
      #     name:       'techhumans.com',
      #     type:       Types::GPOS,
      #     ttl:        1234,
      #     longitude:  '10.0',
      #     latitude:   '20.0',
      #     altitude:   '30.0',
      #  }
      #
      # Since the type is assumed to be GPOS, it will be assigned
      # automatially, and any other value will be overwritten.
      # Therefore, having it present in the hash is not necessary.

      def self.new_from_hash(gpos_params_hash)
        gpos_params_hash[:type] = Types::GPOS
        RR.new_from_hash(gpos_params_hash)
      end


      # Create an instance from a string containing parameters, e.g.:
      # 'a.dnsruby.com.  10800  IN  GPOS  10.0  20.0  30.0'
      def self.new_from_string(gpos_params_string)
        RR.new_from_string(gpos_params_string)
      end


      # Create an instance from an ordered parameter list, e.g.:
      # EXAMPLE_GPOS_DATA = begin
      #   rdata = RR::GPOS.build_rdata(EXAMPLE_LONGITUDE, EXAMPLE_LATITUDE, EXAMPLE_ALTITUDE)
      #   [EXAMPLE_HOSTNAME, Types::GPOS, Classes::IN, EXAMPLE_TTL, rdata.length, rdata, 0]
      # end
      # self.from_data(*EXAMPLE_GPOS_DATA)
      def self.new_from_data(*gpos_params_data)
        RR.new_from_data(*gpos_params_data)
      end


      def from_data(array)
        unless array.size == 3
          raise "Array size for creating GPOS record must be 3 (long, lat, alt). Array was:\n#{array.inspect}"
        end

        from_hash({
                      longitude: array[0],
                      latitude:  array[1],
                      altitude:  array[2]
                  })
      end

      def from_hash(init_data)
        self.class.validate_floats(init_data)
        @longitude = init_data[:longitude].to_s
        @latitude  = init_data[:latitude].to_s
        @altitude  = init_data[:altitude].to_s
        self.rdata = build_rdata
        self
      end

      def from_string(string)
        # Convert commas to spaces, then split by spaces:
        from_data(string.gsub(',', ' ').split(' '))
      end

      # From the RFC:
      #    GPOS has the following format:
      # <owner> <ttl> <class> GPOS <longitude> <latitude> <altitude>
      #
      # We handle the rdata, the RR superclass does the rest.
      def rdata_to_string
        [longitude, latitude, altitude].join(' ')
      end

      def encode_rdata(msg, _canonical)
        msg.put_bytes(build_rdata)
      end

      def build_rdata
        self.class.build_rdata(longitude, latitude, altitude)
      end

      def self.build_rdata(longitude, latitude, altitude)
        binary_string = ''.force_encoding('ASCII-8BIT')

        binary_string << longitude.length.chr
        binary_string << longitude
        binary_string << latitude.length.chr
        binary_string << latitude
        binary_string << altitude.length.chr
        binary_string << altitude
        binary_string
      end

      def self.decode_rdata(message)
        rdata_s = message.get_bytes.clone

        index = 0

        long_len = rdata_s[index].ord;         index += 1
        longitude = rdata_s[index, long_len];  index += long_len

        lat_len = rdata_s[index].ord;          index += 1
        latitude = rdata_s[index, lat_len];    index += lat_len

        alt_len = rdata_s[index].ord;          index += 1
        altitude = rdata_s[index, alt_len];    index += alt_len

        validate_latitude(latitude)
        validate_longitude(longitude)

        new([longitude, latitude, altitude].join(' '))  # e.g. "10.0 20.0 30.0"
      end

      # 'name' is used in the RR superclass, but 'owner' is the term referred to
      # in the RFC, so we'll make owner an alias for name.
      def owner
        name
      end

      # 'name' is used in the RR superclass, but 'owner' is the term referred to
      # in the RFC, so we'll make owner an alias for name.
      def owner=(owner_string)
        self.name = owner_string
      end

      def self.valid_float?(object)
        begin
          Float(object)
          true
        rescue
          false
        end
      end

      def self.validate_float_in_range(label, object, bound)
        number = Float(object)
        valid_range = (-Float(bound)..Float(bound))
        unless valid_range.include?(number)
          raise "Value of #{label} (#{number}) was not in the range #{valid_range}."
        end
      end

      def self.validate_longitude(value)
        validate_float_in_range('longitude', value, 180)
      end

      def self.validate_latitude(value)
        validate_float_in_range('latitude',  value, 90)
      end

      def self.validate_floats(init_data)
        bad_float_keys = REQUIRED_KEYS.reject { |key| valid_float?(init_data[key]) }
        unless bad_float_keys.empty?
          message = "The following key value pair(s) do not have valid floats or float strings:\n"
          bad_float_keys.each do |key|
            message << "%:-12.12s => %s\n" % [init_data[key]]
          end
          raise message
        end

        validate_longitude(init_data[:longitude])
        validate_latitude(init_data[:latitude])
      end
    end
  end
end



