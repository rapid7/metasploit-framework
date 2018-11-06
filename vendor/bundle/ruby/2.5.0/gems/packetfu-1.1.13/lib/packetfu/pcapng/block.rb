# -*- coding: binary -*-
module PacketFu
  module PcapNG

    module Block

      # Calculate block length and update :block_len and block_len2 fields
      def recalc_block_len
        len = to_a.map(&:to_s).join.size
        self[:block_len].value = self[:block_len2].value = len
      end

      # Pad given field to 32 bit boundary, if needed
      def pad_field(*fields)
        fields.each do |field|
          unless self[field].size % 4 == 0
            self[field] << "\x00" * (4 - (self[field].size % 4))
          end
        end
      end

    end

  end
end
