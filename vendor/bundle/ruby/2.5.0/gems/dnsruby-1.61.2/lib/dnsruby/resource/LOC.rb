# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  class RR
      # Class for DNS Location (LOC) resource records.  See RFC 1876 for
      # details.
    class LOC < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::LOC #:nodoc: all

      # The version number of the representation; programs should
      # always check this.  Dnsruby currently supports only version 0.
      attr_accessor :version
      @version = 0

      # The diameter of a sphere enclosing the described entity,
      # in centimeters.
      attr_accessor :size
      # The horizontal precision of the data, in centimeters.
      attr_accessor :horiz_pre
      # The vertical precision of the data, in centimeters.
      attr_accessor :vert_pre
      # The latitude of the center of the sphere described by
      # the size method, in thousandths of a second of arc.  2**31
      # represents the equator; numbers above that are north latitude.
      attr_accessor :latitude
      # The longitude of the center of the sphere described by
      # the size method, in thousandths of a second of arc.  2**31
      # represents the prime meridian; numbers above that are east
      # longitude.
      attr_accessor :longitude
      # The altitude of the center of the sphere described by
      # the size method, in centimeters, from a base of 100,000m
      # below the WGS 84 reference spheroid used by GPS.
      attr_accessor :altitude
      #  Powers of 10 from 0 to 9 (used to speed up calculations).
      POWEROFTEN = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000]

      #  Reference altitude in centimeters (see RFC 1876).
      REFERENCE_ALT = 100_000 * 100;

      #  Reference lat/lon (see RFC 1876).
      REFERENCE_LATLON = 2**31;

      #  Conversions to/from thousandths of a degree.
      CONV_SEC = 1000;
      CONV_MIN = 60 * CONV_SEC;
      CONV_DEG = 60 * CONV_MIN;

      #  Defaults (from RFC 1876, Section 3).
      DEFAULT_MIN       = 0;
      DEFAULT_SEC       = 0;
      DEFAULT_SIZE      = 1;
      DEFAULT_HORIZ_PRE = 10_000;
      DEFAULT_VERT_PRE  = 10;


      def latlon2dms(rawmsec, hems)
        #  Tried to use modulus here, but Perl dumped core if
        #  the value was >= 2**31.

        abs  = (rawmsec - REFERENCE_LATLON).abs;
        deg  = (abs / CONV_DEG).round;
        abs  -= deg * CONV_DEG;
        min  = (abs / CONV_MIN).round;
        abs -= min * CONV_MIN;
        sec  = (abs / CONV_SEC).round;  # $conv_sec
        abs -= sec * CONV_SEC;
        msec = abs;

        hem = hems[(rawmsec >= REFERENCE_LATLON ? 0 : 1), 1]

        return sprintf("%d %02d %02d.%03d %s", deg, min, sec, msec, hem);
      end

      def dms2latlon(deg, min, sec, hem)
        retval=0

        retval = (deg * CONV_DEG) + (min * CONV_MIN) + (sec * CONV_SEC).round;
        retval = -retval if ((hem != nil) && ((hem == "S") || (hem == "W")));
        retval += REFERENCE_LATLON;
        return retval;
      end

      # Returns the latitude and longitude as floating-point degrees.
      # Positive numbers represent north latitude or east longitude;
      # negative numbers represent south latitude or west longitude.
      # 
      #     lat, lon = rr.latlon
      #     system("xearth", "-pos", "fixed #{lat} #{lon}")
      # 
      def latlon
        retlat, retlon = nil

        if (@version == 0)
          retlat = latlon2deg(@latitude);
          retlon = latlon2deg(@longitude);
        end

        return retlat, retlon
      end

      def latlon2deg(rawmsec)
        deg=0;

        deg = (rawmsec - reference_latlon) / CONV_DEG;
        return deg;
      end

      def from_data(data) #:nodoc: all
        @version, @size, @horiz_pre, @vert_pre, @latitude, @longitude, @altitude = data
      end

      def from_string(string) #:nodoc: all
        if (string &&
            string =~ /^ (\d+) \s+		# deg lat
         ((\d+) \s+)?		# min lat
         (([\d.]+) \s+)?	# sec lat
         (N|S) \s+		# hem lat
         (\d+) \s+		# deg lon
         ((\d+) \s+)?		# min lon
         (([\d.]+) \s+)?	# sec lon
         (E|W) \s+		# hem lon
         (-?[\d.]+) m? 	# altitude
         (\s+ ([\d.]+) m?)?	# size
         (\s+ ([\d.]+) m?)?	# horiz precision
         (\s+ ([\d.]+) m?)? 	# vert precision
          /ix)  #

          size = DEFAULT_SIZE

          #  What to do for other versions?
          version = 0;

          horiz_pre = DEFAULT_HORIZ_PRE
          vert_pre  = DEFAULT_VERT_PRE
          latdeg, latmin, latsec, lathem = $1.to_i, $3.to_i, $5.to_f, $6;
          londeg, lonmin, lonsec, lonhem = $7.to_i, $9.to_i, $11.to_f, $12
          alt = $13.to_i
          if ($15)
            size = $15.to_f
          end
          if ($17)
          horiz_pre = $17.to_f
          end
          if ($19)
            vert_pre = $19.to_f
          end

          latmin    = DEFAULT_MIN       unless latmin;
          latsec    = DEFAULT_SEC       unless latsec;
          lathem    = lathem.upcase;

          lonmin    = DEFAULT_MIN       unless lonmin;
          lonsec    = DEFAULT_SEC       unless lonsec;
          lonhem    = lonhem.upcase

          @version   = version;
          @size      = size * 100;
          @horiz_pre = horiz_pre * 100;
          @vert_pre  = vert_pre * 100;
          @latitude  = dms2latlon(latdeg, latmin, latsec, lathem);
          @longitude = dms2latlon(londeg, lonmin, lonsec, lonhem);
          @altitude  = alt * 100 + REFERENCE_ALT;
        end
      end

      def from_hash(hash) #:nodoc: all
        super(hash)
        if (@size == nil)
          @size = DEFAULT_SIZE * 100
        end
        if @horiz_pre == nil
          @horiz_pre = DEFAULT_HORIZ_PRE * 100
        end
        if @vert_pre == nil
          @vert_pre = DEFAULT_VERT_PRE * 100
        end
      end

      def rdata_to_string #:nodoc: all
        rdatastr=""

        if (defined?@version)
          if (@version == 0)
            lat       = @latitude;
            lon       = @longitude;
            altitude  = @altitude;
            size      = @size;
            horiz_pre = @horiz_pre;
            vert_pre  = @vert_pre;

            altitude   = (altitude - REFERENCE_ALT) / 100;
            size      /= 100;
            horiz_pre /= 100;
            vert_pre  /= 100;

            rdatastr = latlon2dms(lat, "NS") + " " +
            latlon2dms(lon, "EW") + " " +
            sprintf("%.2fm", altitude)  + " " +
            sprintf("%.2fm", size)      + " " +
            sprintf("%.2fm", horiz_pre) + " " +
            sprintf("%.2fm", vert_pre);
          else
            rdatastr = "; version " + @version + " not supported";
          end
        else
          rdatastr = '';
        end

        return rdatastr;
      end

      def self.decode_rdata(msg) #:nodoc: all
        version, = msg.get_unpack("C")
        if (version == 0)
          size, horiz_pre, vert_pre, latitude, longitude, altitude = msg.get_unpack('CCCNNN')
          size = precsize_ntoval(size)
          horiz_pre = precsize_ntoval(horiz_pre)
          vert_pre = precsize_ntoval(vert_pre)
          return self.new([version, size, horiz_pre, vert_pre, latitude, longitude, altitude])
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack('C', @version)
        if (@version == 0)
          msg.put_pack('CCCNNN', precsize_valton(@size),
          precsize_valton(@horiz_pre), precsize_valton(@vert_pre),
          @latitude, @longitude, @altitude)
        end
      end

      def self.precsize_ntoval(prec)
        mantissa = ((prec >> 4) & 0x0f) % 10;
        exponent = (prec & 0x0f) % 10;
        return mantissa * POWEROFTEN[exponent];
      end

      def precsize_valton(val)
        exponent = 0;
        while (val >= 10)
          val /= 10;
          exponent+=1
        end
        return (val.round << 4) | (exponent & 0x0f);
      end

    end
  end
end