# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    module PostgreSQL
      #
      # PostgreSQL Page Parser (src/include/storage/bufpage.h)
      #
      module Page
        PAGE_SIZE = 8192
        HEADER_SIZE = 24
        ITEM_ID_SIZE = 4
        HEADER_FORMAT = 'Q<S<S<S<S<S<S<L<'
        HEADER_FIELDS = %i[
          pd_lsn pd_checksum pd_flags pd_lower pd_upper pd_special pd_pagesize_version pd_prune_xid
        ].freeze
        VALID_SIZES = [8192, 16_384, 32_768].freeze

        class << self
          def parse_header(data)
            return unless data&.length&.>= HEADER_SIZE

            values = data.unpack(HEADER_FORMAT)
            build_header(values)
          end

          def parse_item_ids(data, header)
            return [] unless data && header && header[:pd_lower] > HEADER_SIZE

            extract_items(data, header[:pd_lower])
          end

          def extract_tuples(data)
            return [] unless valid?(data)

            header = parse_header(data)
            parse_item_ids(data, header).filter_map { |item| extract_tuple(data, header, item) }
          end

          def valid?(data)
            return false unless data&.length&.>= PAGE_SIZE

            h = parse_header(data)
            valid_header?(h)
          end

          private

          def build_header(values)
            HEADER_FIELDS.zip(values).to_h.merge(
              page_size: values[6] & 0xFF00,
              version: values[6] & 0x00FF
            )
          end

          def extract_items(data, pd_lower)
            (HEADER_SIZE...pd_lower).step(ITEM_ID_SIZE).map.with_index(1) do |offset, num|
              raw = data[offset, ITEM_ID_SIZE].unpack1('L<')
              { num: num, off: raw & 0x7FFF, flags: (raw >> 15) & 0x03, len: (raw >> 17) & 0x7FFF }
            end
          end

          def extract_tuple(data, header, item)
            return unless item[:flags] == 1 && item[:len].positive?
            return unless item[:off] >= header[:pd_upper] && item[:off] + item[:len] <= PAGE_SIZE

            tuple = HeapTuple.parse(data[item[:off], item[:len]])
            { item: item, tuple: tuple } if tuple
          end

          def valid_header?(hdr)
            return false unless hdr

            VALID_SIZES.include?(hdr[:page_size]) && hdr[:version].between?(1, 10) &&
              hdr[:pd_lower] >= HEADER_SIZE && hdr[:pd_upper] <= hdr[:page_size] && hdr[:pd_lower] <= hdr[:pd_upper]
          end
        end
      end
    end
  end
end
