# -*- coding: binary -*-
# frozen_string_literal: true

require 'date'

module Rex
  module Proto
    module PostgreSQL
      # PostgreSQL Type Decoder
      module Types
        PG_EPOCH = 946_684_800
        USEC = 1_000_000

        OIDS = {
          bool: 16, bytea: 17, char: 18, name: 19, int8: 20, int2: 21, int4: 23, text: 25, oid: 26,
          json: 114, float4: 700, float8: 701, inet: 869, macaddr: 829, time: 1083, date: 1082,
          timestamp: 1114, timestamptz: 1184, interval: 1186, varchar: 1043, uuid: 2950,
          numeric: 1700, jsonb: 3802,
          bool_array: 1000, int2_array: 1005, int4_array: 1007, int8_array: 1016,
          text_array: 1009, float8_array: 1022, varchar_array: 1015, jsonb_array: 3807
        }.freeze

        OID_TO_TYPE = OIDS.invert.freeze

        ARRAY_ELEM = {
          1000 => 16, 1005 => 21, 1007 => 23, 1016 => 20, 1009 => 25,
          1022 => 701, 1015 => 1043, 3807 => 3802
        }.freeze

        class << self
          def decode(data, oid, *)
            return if data.nil? || data.empty?

            ARRAY_ELEM[oid] ? decode_array(data, ARRAY_ELEM[oid]) : decode_scalar(data, oid)
          rescue StandardError
            safe_string(data)
          end

          def read_varlena(data)
            return [nil, 0] if data.nil? || data.empty?

            # Skip padding bytes (0x00) - PostgreSQL uses these for alignment
            pad = 0
            pad += 1 while pad < data.length && data[pad].unpack1('C').zero?
            return [nil, pad] if pad >= data.length

            first = data[pad].unpack1('C')
            if (first & 0x01).zero?
              val, consumed = read_long_varlena(data[pad..])
              [val, pad + consumed]
            elsif first == 0x01
              [nil, pad + 1]
            else
              len = (first >> 1) - 1
              len >= 0 && data.length >= pad + 1 + len ? [data[pad + 1, len], pad + 1 + len] : [nil, pad]
            end
          end

          def type_name(oid)
            OID_TO_TYPE[oid]&.to_s || "oid:#{oid}"
          end

          def safe_string(data)
            data.dup.force_encoding('UTF-8').scrub('.')
          end

          private

          def decode_scalar(data, oid)
            case oid
            when 16 then data[0].unpack1('C') != 0
            when 17 then "\\x#{data.unpack1('H*')}"
            when 18 then data[0]
            when 19 then data[0, 64].unpack1('Z64')
            when 20 then data[0, 8].unpack1('q<')
            when 21 then data[0, 2].unpack1('s<')
            when 23 then data[0, 4].unpack1('l<')
            when 25, 1043 then safe_string(data)
            when 26 then data[0, 4].unpack1('L<')
            when 114 then safe_string(data)
            when 700 then data[0, 4].unpack1('e')
            when 701 then data[0, 8].unpack1('E')
            when 829 then decode_macaddr(data)
            when 869 then decode_inet(data)
            when 1082 then decode_date(data)
            when 1083 then decode_time(data)
            when 1114, 1184 then decode_timestamp(data)
            when 1186 then decode_interval(data)
            when 1700 then decode_numeric(data)
            when 2950 then decode_uuid(data)
            when 3802 then Jsonb.parse(data) || safe_string(data)
            else safe_string(data)
            end
          end

          def decode_macaddr(data)
            data[0, 6].unpack('C6').map { |b| format('%02x', b) }.join(':')
          end

          def decode_inet(data)
            return nil if data.length < 2

            family = data[0].unpack1('C')
            _bits = data[1].unpack1('C')

            if family == 2 && data.length >= 6
              data[2, 4].unpack('C4').join('.')
            elsif family == 3 && data.length >= 18
              data[2, 16].unpack('n8').map { |w| format('%x', w) }.join(':')
            else
              "inet:#{data.unpack1('H*')}"
            end
          end

          def decode_date(data)
            days = data[0, 4].unpack1('l<')
            (Date.new(2000, 1, 1) + days).to_s
          rescue StandardError
            "date:#{days}"
          end

          def decode_time(data)
            usec = data[0, 8].unpack1('q<')
            hours = usec / (3600 * USEC)
            mins = (usec / (60 * USEC)) % 60
            secs = (usec / USEC) % 60
            format('%<h>02d:%<m>02d:%<s>02d', h: hours, m: mins, s: secs)
          rescue StandardError
            'time:?'
          end

          def decode_timestamp(data)
            usec = data[0, 8].unpack1('q<')
            Time.at(PG_EPOCH + usec / USEC).utc.strftime('%F %T')
          rescue StandardError
            'ts:?'
          end

          def decode_interval(data)
            return 'interval:?' if data.length < 16

            usec = data[0, 8].unpack1('q<')
            days = data[8, 4].unpack1('l<')
            months = data[12, 4].unpack1('l<')

            parts = []
            parts << "#{months / 12}y" if months >= 12
            parts << "#{months % 12}mo" if (months % 12).positive?
            parts << "#{days}d" if days.positive?
            parts << "#{usec / (3600 * USEC)}h" if usec >= 3600 * USEC
            parts << "#{(usec / (60 * USEC)) % 60}m" if usec >= 60 * USEC && (usec / (60 * USEC)) % 60 > 0
            parts.empty? ? '0' : parts.join(' ')
          rescue StandardError
            'interval:?'
          end

          def decode_numeric(data)
            Jsonb.parse_numeric(data) || "num:#{data.unpack1('H*')}"
          end

          def decode_uuid(data)
            return nil if data.length < 16

            hex = data[0, 16].unpack1('H32')
            "#{hex[0, 8]}-#{hex[8, 4]}-#{hex[12, 4]}-#{hex[16, 4]}-#{hex[20, 12]}"
          end

          def decode_array(raw, elem_oid)
            return [] if raw.nil? || raw.length < 20

            ndim = raw[0, 4].unpack1('l<')
            return [] unless ndim.positive? && ndim <= 6

            dataoffset = raw[4, 4].unpack1('l<')
            _elem_type = raw[8, 4].unpack1('L<')

            # Read dimensions
            dims = ndim.times.map { |i| raw[12 + i * 4, 4].unpack1('l<') }
            total_elements = dims.reduce(1, :*)
            return [] if total_elements <= 0

            # Null bitmap if dataoffset != 0
            nullbitmap = dataoffset.positive? ? raw[12 + ndim * 8, (total_elements + 7) / 8] : nil

            # Data starts after dims + lbounds (+ nullbitmap if present)
            data_start = dataoffset.positive? ? dataoffset : 12 + ndim * 8
            elem_len = FIXED_TYPE_LENGTHS[elem_oid]

            parse_array_data(raw, data_start, total_elements, elem_oid, elem_len, nullbitmap)
          end

          FIXED_TYPE_LENGTHS = {
            16 => 1, 18 => 1, 21 => 2, 23 => 4, 20 => 8, 26 => 4,
            700 => 4, 701 => 8, 1082 => 4, 1114 => 8, 1184 => 8
          }.freeze

          def parse_array_data(raw, offset, count, elem_oid, elem_len, nullbitmap)
            elements = []
            count.times do |i|
              if nullbitmap && (nullbitmap[i / 8].ord & (1 << (i % 8))).zero?
                elements << nil
                next
              end

              if elem_len
                # Fixed-length type
                elements << decode(raw[offset, elem_len], elem_oid)
                offset += elem_len
              else
                # Varlena type - read header
                offset = (offset + 3) & ~3 if i.positive? # INTALIGN between elements
                break if offset >= raw.length

                hdr = raw[offset].unpack1('C')
                if (hdr & 1) == 1
                  total = hdr >> 1
                  elements << decode(raw[offset + 1, total - 1], elem_oid)
                else
                  total = raw[offset, 4].unpack1('L<') >> 2
                  elements << decode(raw[offset + 4, total - 4], elem_oid)
                end
                offset += total
              end
            end
            elements
          end

          def read_long_varlena(data)
            return [nil, 0] if data.length < 4

            len = (data[0, 4].unpack1('L<') >> 2) - 4
            len >= 0 && data.length >= 4 + len ? [data[4, len], 4 + len] : [nil, 0]
          end
        end
      end
    end
  end
end
