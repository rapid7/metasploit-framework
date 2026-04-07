# -*- coding: binary -*-
# frozen_string_literal: true

require 'set'

module Rex
  module Proto
    module PostgreSQL
      #
      # PostgreSQL JSONB binary format parser (src/include/utils/jsonb.h)
      #
      module Jsonb
        # Header flags
        JB_CMASK = 0x0FFFFFFF
        JB_FSCALAR = 0x10000000
        JB_FOBJECT = 0x20000000
        JB_FARRAY = 0x40000000

        # JEntry flags
        JE_OFFLENMASK = 0x0FFFFFFF
        JE_HAS_OFF = 0x80000000

        # JEntry type flags (bits 28-30) from PostgreSQL jsonb.h
        JE_ISSTRING = 0x00000000
        JE_ISNUMERIC = 0x10000000
        JE_ISBOOL_FALSE = 0x20000000
        JE_ISBOOL_TRUE = 0x30000000
        JE_ISNULL = 0x40000000
        JE_ISCONTAINER = 0x50000000

        class << self
          def parse(data)
            return if data.nil? || data.length < 4

            header = data[0, 4].unpack1('V')
            count = header & JB_CMASK
            is_obj = (header & JB_FOBJECT) != 0
            is_arr = (header & JB_FARRAY) != 0
            is_scalar = (header & JB_FSCALAR) != 0

            return unless (is_obj || is_arr) && count.positive? && count <= 10_000

            num_entries = is_obj ? count * 2 : count
            return if 4 + num_entries * 4 > data.length

            entries = num_entries.times.map { |i| data[4 + i * 4, 4].unpack1('V') }
            data_start = 4 + num_entries * 4

            result = is_obj ? parse_object(data, entries, data_start, count) : parse_array(data, entries, data_start, count)

            is_scalar && result.is_a?(Array) && result.length == 1 ? result.first : result
          rescue StandardError
            nil
          end

          def scan_objects(content, **opts)
            Scanner.new(content, opts).run
          end

          def parse_numeric(raw)
            NumericDecoder.decode(raw)
          end

          private

          def parse_object(data, entries, data_start, count)
            # Calculate total length of all keys
            key_entries = entries[0, count]
            val_entries = entries[count, count]

            keys_total_len = calc_total_length(key_entries)

            result = {}
            count.times do |i|
              key_off, key_len = calc_entry_offset_len(key_entries, i, 0)
              key = data[data_start + key_off, key_len]&.force_encoding('UTF-8') || ''

              val_off, val_len = calc_entry_offset_len(val_entries, i, keys_total_len)
              val = decode_value(data, data_start + val_off, val_len, val_entries[i])

              result[key] = val
            end
            result
          end

          def parse_array(data, entries, data_start, count)
            count.times.map do |i|
              off, len = calc_entry_offset_len(entries, i, 0)
              decode_value(data, data_start + off, len, entries[i])
            end
          end

          def calc_total_length(entries)
            return 0 if entries.empty?

            # End offset of last entry = total length
            find_prev_end_offset(entries, entries.length - 1)
          end

          def calc_entry_offset_len(entries, idx, base_offset)
            je = entries[idx]
            val = je & JE_OFFLENMASK

            start_off = idx.zero? ? 0 : find_prev_end_offset(entries, idx - 1)
            if (je & JE_HAS_OFF) != 0
              # val is end offset, need to find start
              [base_offset + start_off, val - start_off]
            else
              # val is length, calculate offset from previous entries
              [base_offset + start_off, val]
            end
          end

          def find_prev_end_offset(entries, idx)
            # Walk backwards to find an entry with HAS_OFF
            (idx).downto(0) do |i|
              je = entries[i]
              next unless (je & JE_HAS_OFF) != 0

              # Found HAS_OFF at position i - its value is end offset of entry[i]
              base = je & JE_OFFLENMASK
              # Add lengths of entries from i+1 to idx
              extra = entries[(i + 1)..idx].sum { |e| e & JE_OFFLENMASK }
              return base + extra
            end
            # No HAS_OFF found, sum all lengths from 0 to idx
            entries[0..idx].sum { |e| e & JE_OFFLENMASK }
          end

          def decode_value(data, offset, len, je)
            typ = je & 0x70000000

            case typ
            when JE_ISSTRING
              return nil if offset + len > data.length

              data[offset, len]&.force_encoding('UTF-8')
            when JE_ISNUMERIC
              decode_numeric_value(data, offset, len)
            when JE_ISCONTAINER
              # Containers are INTALIGN'd, padding is included in len
              aligned_off = (offset + 3) & ~3
              padding = aligned_off - offset
              actual_len = len - padding
              return nil if aligned_off + actual_len > data.length

              parse(data[aligned_off, actual_len])
            when JE_ISNULL then nil
            when JE_ISBOOL_FALSE then false
            when JE_ISBOOL_TRUE then true
            else
              return nil if offset + len > data.length

              data[offset, len]&.force_encoding('UTF-8')
            end
          end

          def decode_numeric_value(data, offset, len)
            # Numeric in JSONB is INTALIGN'd and includes varlena header
            # Find aligned position within the len bytes
            aligned_off = (offset + 3) & ~3
            padding = aligned_off - offset
            return nil if padding >= len

            varlena_data = data[aligned_off, len - padding]
            return nil if varlena_data.nil? || varlena_data.length < 4

            # Read varlena header (little-endian)
            vl_header = varlena_data[0, 4].unpack1('L<')
            if (vl_header & 3).zero?
              # Long varlena: size = header >> 2
              vl_len = vl_header >> 2
              numeric_content = varlena_data[4, vl_len - 4]
            else
              # Short varlena: size = (header & 0xFF) >> 1
              vl_len = (vl_header & 0xFF) >> 1
              numeric_content = varlena_data[1, vl_len - 1]
            end

            parse_numeric(numeric_content)
          end
        end

        # Numeric decoder - PostgreSQL on-disk format (little-endian short format)
        module NumericDecoder
          NBASE = 10_000
          NUMERIC_SHORT = 0x8000
          NUMERIC_SHORT_SIGN_MASK = 0x2000
          NUMERIC_SHORT_WEIGHT_SIGN_MASK = 0x0040
          NUMERIC_SHORT_WEIGHT_MASK = 0x003F

          def self.decode(raw)
            return if raw.nil? || raw.length < 2

            header = raw[0, 2].unpack1('v') # Little-endian

            if (header & NUMERIC_SHORT) != 0
              decode_short(raw, header)
            else
              decode_long(raw)
            end
          rescue StandardError
            nil
          end

          def self.decode_short(raw, header)
            sign = (header & NUMERIC_SHORT_SIGN_MASK) != 0 ? -1 : 1
            weight = header & NUMERIC_SHORT_WEIGHT_MASK
            weight = -weight - 1 if (header & NUMERIC_SHORT_WEIGHT_SIGN_MASK) != 0

            ndigits = (raw.length - 2) / 2
            return 0 if ndigits.zero?

            digits = ndigits.times.map { |i| raw[2 + i * 2, 2].unpack1('v') } # Little-endian
            compute_value(digits, weight, sign)
          end

          def self.decode_long(raw)
            return if raw.length < 8

            ndigits = raw[0, 2].unpack1('v')
            weight = raw[2, 2].unpack1('v')
            weight = weight > 32767 ? weight - 65536 : weight
            sign_raw = raw[4, 2].unpack1('v')
            sign = sign_raw == 0x4000 ? -1 : 1

            return 0 if ndigits.zero?
            return nil if raw.length < 8 + ndigits * 2

            digits = ndigits.times.map { |i| raw[8 + i * 2, 2].unpack1('v') } # Little-endian
            compute_value(digits, weight, sign)
          end

          def self.compute_value(digits, weight, sign)
            return 0 if digits.empty?

            result = digits.reduce(0) { |acc, d| acc * NBASE + d }
            exp = weight - digits.length + 1

            result = if exp >= 0
                       result * (NBASE**exp)
                     elsif exp.abs <= 6
                       Rational(result, NBASE**(-exp)).to_f
                     else
                       Rational(result, NBASE**(-exp))
                     end

            sign * result
          end
        end

        # Scanner for finding JSONB objects in raw data
        class Scanner
          def initialize(content, opts)
            @content = content
            @filter_keys = opts[:filter_keys]
            @min_keys = opts[:min_keys] || 2
            @max_keys = opts[:max_keys] || 50
            @max_blob_size = opts[:max_blob_size] || 2000
            @seen = Set.new
            @results = []
          end

          def run
            (0...(@content.length - 50)).each { |i| try_parse(i) }
            @results
          end

          private

          def try_parse(pos)
            header = @content[pos, 4]&.unpack1('V')
            return unless header

            count = header & JB_CMASK
            return unless (header & JB_FOBJECT) != 0 && count.between?(@min_keys, @max_keys)

            parsed = Jsonb.parse(@content[pos, @max_blob_size])
            add_result(parsed)
          rescue StandardError
            nil
          end

          def add_result(obj)
            return unless obj.is_a?(Hash) && !obj.empty?
            return if @filter_keys && !matches_filter?(obj)

            sig = obj.to_a.sort.hash
            @results << obj if @seen.add?(sig)
          end

          def matches_filter?(obj)
            keys = obj.keys.map { |k| k.to_s.downcase }
            @filter_keys.any? { |f| keys.any? { |k| k.include?(f.downcase) } }
          end
        end
      end
    end
  end
end
