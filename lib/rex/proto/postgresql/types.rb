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

        # PostgreSQL type OIDs (from pg_type.dat)
        OID_BOOL        = 16
        OID_BYTEA       = 17
        OID_CHAR        = 18
        OID_NAME        = 19
        OID_INT8        = 20
        OID_INT2        = 21
        OID_INT4        = 23
        OID_TEXT        = 25
        OID_OID         = 26
        OID_JSON        = 114
        OID_FLOAT4      = 700
        OID_FLOAT8      = 701
        OID_MACADDR     = 829
        OID_INET        = 869
        OID_VARCHAR     = 1043
        OID_DATE        = 1082
        OID_TIME        = 1083
        OID_TIMESTAMP   = 1114
        OID_TIMESTAMPTZ = 1184
        OID_INTERVAL    = 1186
        OID_NUMERIC     = 1700
        OID_UUID        = 2950
        OID_JSONB       = 3802

        # Array type OIDs
        OID_BOOL_ARRAY    = 1000
        OID_INT2_ARRAY    = 1005
        OID_INT4_ARRAY    = 1007
        OID_VARCHAR_ARRAY = 1015
        OID_INT8_ARRAY    = 1016
        OID_TEXT_ARRAY    = 1009
        OID_FLOAT8_ARRAY  = 1022
        OID_JSONB_ARRAY   = 3807

        OIDS = {
          bool: OID_BOOL, bytea: OID_BYTEA, char: OID_CHAR, name: OID_NAME,
          int8: OID_INT8, int2: OID_INT2, int4: OID_INT4, text: OID_TEXT, oid: OID_OID,
          json: OID_JSON, float4: OID_FLOAT4, float8: OID_FLOAT8, inet: OID_INET,
          macaddr: OID_MACADDR, time: OID_TIME, date: OID_DATE,
          timestamp: OID_TIMESTAMP, timestamptz: OID_TIMESTAMPTZ, interval: OID_INTERVAL,
          varchar: OID_VARCHAR, uuid: OID_UUID, numeric: OID_NUMERIC, jsonb: OID_JSONB,
          bool_array: OID_BOOL_ARRAY, int2_array: OID_INT2_ARRAY, int4_array: OID_INT4_ARRAY,
          int8_array: OID_INT8_ARRAY, text_array: OID_TEXT_ARRAY, float8_array: OID_FLOAT8_ARRAY,
          varchar_array: OID_VARCHAR_ARRAY, jsonb_array: OID_JSONB_ARRAY
        }.freeze

        OID_TO_TYPE = OIDS.invert.freeze

        ARRAY_ELEM = {
          OID_BOOL_ARRAY => OID_BOOL, OID_INT2_ARRAY => OID_INT2,
          OID_INT4_ARRAY => OID_INT4, OID_INT8_ARRAY => OID_INT8,
          OID_TEXT_ARRAY => OID_TEXT, OID_FLOAT8_ARRAY => OID_FLOAT8,
          OID_VARCHAR_ARRAY => OID_VARCHAR, OID_JSONB_ARRAY => OID_JSONB
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
            when OID_BOOL then data[0].unpack1('C') != 0
            when OID_BYTEA then "\\x#{data.unpack1('H*')}"
            when OID_CHAR then data[0]
            when OID_NAME then data[0, 64].unpack1('Z64')
            when OID_INT8 then data[0, 8].unpack1('q<')
            when OID_INT2 then data[0, 2].unpack1('s<')
            when OID_INT4 then data[0, 4].unpack1('l<')
            when OID_TEXT, OID_VARCHAR then safe_string(data)
            when OID_OID then data[0, 4].unpack1('L<')
            when OID_JSON then safe_string(data)
            when OID_FLOAT4 then data[0, 4].unpack1('e')
            when OID_FLOAT8 then data[0, 8].unpack1('E')
            when OID_MACADDR then decode_macaddr(data)
            when OID_INET then decode_inet(data)
            when OID_DATE then decode_date(data)
            when OID_TIME then decode_time(data)
            when OID_TIMESTAMP, OID_TIMESTAMPTZ then decode_timestamp(data)
            when OID_INTERVAL then decode_interval(data)
            when OID_NUMERIC then decode_numeric(data)
            when OID_UUID then decode_uuid(data)
            when OID_JSONB then Jsonb.parse(data) || safe_string(data)
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
            OID_BOOL => 1, OID_CHAR => 1, OID_INT2 => 2, OID_INT4 => 4,
            OID_INT8 => 8, OID_OID => 4, OID_FLOAT4 => 4, OID_FLOAT8 => 8,
            OID_DATE => 4, OID_TIMESTAMP => 8, OID_TIMESTAMPTZ => 8
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
