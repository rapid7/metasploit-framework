# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    module PostgreSQL
      #
      # PostgreSQL Heap Tuple Parser (src/include/access/htup_details.h)
      #
      module HeapTuple
        HEADER_SIZE = 23
        NATTS_MASK = 0x07FF

        # t_infomask flags
        MASK_FLAGS = {
          has_null: 0x0001, has_varwidth: 0x0002, has_external: 0x0004,
          xmin_committed: 0x0100, xmin_invalid: 0x0200,
          xmax_committed: 0x0400, xmax_invalid: 0x0800
        }.freeze

        # t_infomask2 flags
        MASK2_FLAGS = { hot_updated: 0x4000, heap_only: 0x8000 }.freeze

        class << self
          def parse(data)
            return unless data&.length&.>= HEADER_SIZE

            header = parse_header(data)
            return unless header[:t_hoff] <= data.length

            { header: header, bitmap: extract_bitmap(data, header), data: data[header[:t_hoff]..] }
          end

          def parse_header(data)
            raw = unpack_header(data)
            build_header(raw)
          end

          def visible?(header)
            header && header[:xmin_committed] && (header[:xmax_invalid] || !header[:xmax_committed])
          end

          def null?(bitmap, attnum)
            return false unless bitmap && attnum.positive?

            byte, bit = (attnum - 1).divmod(8)
            byte >= bitmap.length || bitmap[byte].nobits?(1 << bit)
          end

          private

          def unpack_header(data)
            {
              t_xmin: data[0, 4].unpack1('L<'),
              t_xmax: data[4, 4].unpack1('L<'),
              t_cid: data[8, 4].unpack1('L<'),
              block: data[12, 4].unpack1('L<'),
              offset: data[16, 2].unpack1('S<'),
              infomask2: data[18, 2].unpack1('S<'),
              infomask: data[20, 2].unpack1('S<'),
              t_hoff: data[22].unpack1('C')
            }
          end

          def build_header(raw)
            {
              t_xmin: raw[:t_xmin], t_xmax: raw[:t_xmax], t_cid: raw[:t_cid],
              t_ctid: { block: raw[:block], offset: raw[:offset] },
              t_infomask: raw[:infomask], t_infomask2: raw[:infomask2], t_hoff: raw[:t_hoff],
              natts: raw[:infomask2] & NATTS_MASK,
              **flags_to_bools(raw[:infomask], MASK_FLAGS),
              **flags_to_bools(raw[:infomask2], MASK2_FLAGS)
            }
          end

          def flags_to_bools(mask, flags)
            flags.transform_values { |v| mask.anybits?(v) }
          end

          def extract_bitmap(data, header)
            return unless header[:has_null]

            bytes = (header[:natts] + 7) / 8
            data[HEADER_SIZE, bytes]&.unpack('C*') if data.length >= HEADER_SIZE + bytes
          end
        end
      end
    end
  end
end
