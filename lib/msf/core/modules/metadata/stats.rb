# frozen_string_literal: true

module Msf
  module Modules
    module Metadata
      module Stats
        attr_reader :module_counts

        def update_stats
          @metadata = get_metadata
          map_types_to_metadata!

          @module_counts = {
            exploit: @module_metadata_by_type['exploit'].size,
            auxiliary: @module_metadata_by_type['auxiliary'].size,
            post: @module_metadata_by_type['post'].size,
            payload: @module_metadata_by_type['payload'].size,
            encoder: @module_metadata_by_type['encoder'].size,
            nop: @module_metadata_by_type['nop'].size,
            evasion: @module_metadata_by_type['evasion'].size,
            total: @metadata.size
          }
        end

        private

        def map_types_to_metadata!
          @module_metadata_by_type = Hash.new { |h, k| h[k] = [] }

          @metadata.each do |module_metadata|
            @module_metadata_by_type[module_metadata.type] << module_metadata
          end
        end
      end
    end
  end
end
