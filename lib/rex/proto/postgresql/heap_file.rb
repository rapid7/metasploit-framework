# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    module PostgreSQL
      #
      # PostgreSQL Heap File Reader - High-level interface
      #
      module HeapFile
        class << self
          def read_tuples(data, visible_only: true, page_size: Page::PAGE_SIZE)
            return [] if data.nil? || data.empty?

            (0...data.length).step(page_size).flat_map { |off| extract_page_tuples(data, off, page_size, visible_only) }
          end

          def read_rows(data, columns, **opts)
            read_tuples(data, **opts).filter_map { |t| decode_tuple(t[:tuple], columns) }
          end

          def decode_tuple(tuple, columns)
            return unless tuple&.dig(:data)

            decode_columns(tuple, columns)
          rescue StandardError
            nil
          end

          private

          def extract_page_tuples(data, offset, page_size, visible_only)
            page = data[offset, page_size]
            return [] unless Page.valid?(page)

            Page.extract_tuples(page).filter_map do |entry|
              next if visible_only && !HeapTuple.visible?(entry[:tuple][:header])

              entry.merge(page_offset: offset)
            end
          end

          def decode_columns(tuple, columns)
            offset = 0
            columns.each_with_index.to_h do |col, idx|
              name = col[:name] || "col#{idx + 1}"
              offset = align_offset(offset, col[:typid], col[:len])
              val, consumed = decode_column(tuple, col, idx, offset)
              offset += consumed
              [name, val]
            end
          end

          def decode_column(tuple, col, idx, offset)
            num = col[:num] || (idx + 1)
            return [nil, 0] if HeapTuple.null?(tuple[:bitmap], num)

            read_value(tuple[:data], offset, col[:typid] || 25, col[:len] || -1)
          end

          def align_offset(offset, typid, len)
            align = type_alignment(typid, len)
            align <= 1 ? offset : (offset + align - 1) & ~(align - 1)
          end

          def type_alignment(typid, len)
            return 1 if len == -1
            return 8 if [20, 701, 1114, 1184].include?(typid)
            return 4 if [23, 26, 700].include?(typid) || len == 4
            return 2 if typid == 21 || len == 2

            1
          end

          def read_value(data, offset, typid, len)
            return [nil, 0] if offset >= data.length

            remaining = data[offset..]
            return [Types.decode(remaining[0, len], typid), len] if len.positive?
            return read_varlena_value(remaining, typid) if len == -1

            read_cstring(remaining)
          end

          def read_varlena_value(data, oid)
            val, consumed = Types.read_varlena(data)
            val ? [Types.decode(val, oid), consumed] : [nil, 1]
          end

          def read_cstring(data)
            idx = data.index("\x00") || data.length
            [data[0, idx], idx + 1]
          end
        end
      end
    end
  end
end
