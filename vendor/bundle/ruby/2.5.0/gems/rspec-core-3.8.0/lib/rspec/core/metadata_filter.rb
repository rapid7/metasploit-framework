module RSpec
  module Core
    # Contains metadata filtering logic. This has been extracted from
    # the metadata classes because it operates ON a metadata hash but
    # does not manage any of the state in the hash. We're moving towards
    # having metadata be a raw hash (not a custom subclass), so externalizing
    # this filtering logic helps us move in that direction.
    module MetadataFilter
      class << self
        # @private
        def apply?(predicate, filters, metadata)
          filters.__send__(predicate) { |k, v| filter_applies?(k, v, metadata) }
        end

        # @private
        def filter_applies?(key, filter_value, metadata)
          silence_metadata_example_group_deprecations do
            return location_filter_applies?(filter_value, metadata) if key == :locations
            return id_filter_applies?(filter_value, metadata)       if key == :ids
            return filters_apply?(key, filter_value, metadata)      if Hash === filter_value

            meta_value = metadata.fetch(key) { return false }

            return true if TrueClass === filter_value && meta_value
            return proc_filter_applies?(key, filter_value, metadata) if Proc === filter_value
            return filter_applies_to_any_value?(key, filter_value, metadata) if Array === meta_value

            filter_value === meta_value || filter_value.to_s == meta_value.to_s
          end
        end

        # @private
        def silence_metadata_example_group_deprecations
          RSpec::Support.thread_local_data[:silence_metadata_example_group_deprecations] = true
          yield
        ensure
          RSpec::Support.thread_local_data.delete(:silence_metadata_example_group_deprecations)
        end

      private

        def filter_applies_to_any_value?(key, value, metadata)
          metadata[key].any? { |v| filter_applies?(key, v,  key => value) }
        end

        def id_filter_applies?(rerun_paths_to_scoped_ids, metadata)
          scoped_ids = rerun_paths_to_scoped_ids.fetch(metadata[:rerun_file_path]) { return false }

          Metadata.ascend(metadata).any? do |meta|
            scoped_ids.include?(meta[:scoped_id])
          end
        end

        def location_filter_applies?(locations, metadata)
          Metadata.ascend(metadata).any? do |meta|
            file_path = meta[:absolute_file_path]
            line_num  = meta[:line_number]

            locations[file_path].any? do |filter_line_num|
              line_num == RSpec.world.preceding_declaration_line(file_path, filter_line_num)
            end
          end
        end

        def proc_filter_applies?(key, proc, metadata)
          case proc.arity
          when 0 then proc.call
          when 2 then proc.call(metadata[key], metadata)
          else proc.call(metadata[key])
          end
        end

        def filters_apply?(key, value, metadata)
          subhash = metadata[key]
          return false unless Hash === subhash || HashImitatable === subhash
          value.all? { |k, v| filter_applies?(k, v, subhash) }
        end
      end
    end

    # Tracks a collection of filterable items (e.g. modules, hooks, etc)
    # and provides an optimized API to get the applicable items for the
    # metadata of an example or example group.
    #
    # There are two implementations, optimized for different uses.
    # @private
    module FilterableItemRepository
      # This implementation is simple, and is optimized for frequent
      # updates but rare queries. `append` and `prepend` do no extra
      # processing, and no internal memoization is done, since this
      # is not optimized for queries.
      #
      # This is ideal for use by a example or example group, which may
      # be updated multiple times with globally configured hooks, etc,
      # but will not be queried frequently by other examples or examle
      # groups.
      # @private
      class UpdateOptimized
        attr_reader :items_and_filters

        def initialize(applies_predicate)
          @applies_predicate = applies_predicate
          @items_and_filters = []
        end

        def append(item, metadata)
          @items_and_filters << [item, metadata]
        end

        def prepend(item, metadata)
          @items_and_filters.unshift [item, metadata]
        end

        def delete(item, metadata)
          @items_and_filters.delete [item, metadata]
        end

        def items_for(request_meta)
          @items_and_filters.each_with_object([]) do |(item, item_meta), to_return|
            to_return << item if item_meta.empty? ||
                                 MetadataFilter.apply?(@applies_predicate, item_meta, request_meta)
          end
        end

        unless [].respond_to?(:each_with_object) # For 1.8.7
          # :nocov:
          undef items_for
          def items_for(request_meta)
            @items_and_filters.inject([]) do |to_return, (item, item_meta)|
              to_return << item if item_meta.empty? ||
                                   MetadataFilter.apply?(@applies_predicate, item_meta, request_meta)
              to_return
            end
          end
          # :nocov:
        end
      end

      # This implementation is much more complex, and is optimized for
      # rare (or hopefully no) updates once the queries start. Updates
      # incur a cost as it has to clear the memoization and keep track
      # of applicable keys. Queries will be O(N) the first time an item
      # is provided with a given set of applicable metadata; subsequent
      # queries with items with the same set of applicable metadata will
      # be O(1) due to internal memoization.
      #
      # This is ideal for use by config, where filterable items (e.g. hooks)
      # are typically added at the start of the process (e.g. in `spec_helper`)
      # and then repeatedly queried as example groups and examples are defined.
      # @private
      class QueryOptimized < UpdateOptimized
        alias find_items_for items_for
        private :find_items_for

        def initialize(applies_predicate)
          super
          @applicable_keys   = Set.new
          @proc_keys         = Set.new
          @memoized_lookups  = Hash.new do |hash, applicable_metadata|
            hash[applicable_metadata] = find_items_for(applicable_metadata)
          end
        end

        def append(item, metadata)
          super
          handle_mutation(metadata)
        end

        def prepend(item, metadata)
          super
          handle_mutation(metadata)
        end

        def delete(item, metadata)
          super
          reconstruct_caches
        end

        def items_for(metadata)
          # The filtering of `metadata` to `applicable_metadata` is the key thing
          # that makes the memoization actually useful in practice, since each
          # example and example group have different metadata (e.g. location and
          # description). By filtering to the metadata keys our items care about,
          # we can ignore extra metadata keys that differ for each example/group.
          # For example, given `config.include DBHelpers, :db`, example groups
          # can be split into these two sets: those that are tagged with `:db` and those
          # that are not. For each set, this method for the first group in the set is
          # still an `O(N)` calculation, but all subsequent groups in the set will be
          # constant time lookups when they call this method.
          applicable_metadata = applicable_metadata_from(metadata)

          if applicable_metadata.any? { |k, _| @proc_keys.include?(k) }
            # It's unsafe to memoize lookups involving procs (since they can
            # be non-deterministic), so we skip the memoization in this case.
            find_items_for(applicable_metadata)
          else
            @memoized_lookups[applicable_metadata]
          end
        end

      private

        def reconstruct_caches
          @applicable_keys.clear
          @proc_keys.clear
          @items_and_filters.each do |_item, metadata|
            handle_mutation(metadata)
          end
        end

        def handle_mutation(metadata)
          @applicable_keys.merge(metadata.keys)
          @proc_keys.merge(proc_keys_from metadata)
          @memoized_lookups.clear
        end

        def applicable_metadata_from(metadata)
          MetadataFilter.silence_metadata_example_group_deprecations do
            @applicable_keys.inject({}) do |hash, key|
              # :example_group is treated special here because...
              # - In RSpec 2, example groups had an `:example_group` key
              # - In RSpec 3, that key is deprecated (it was confusing!).
              # - The key is not technically present in an example group metadata hash
              #   (and thus would fail the `metadata.key?(key)` check) but a value
              #   is provided when accessed via the hash's `default_proc`
              # - Thus, for backwards compatibility, we have to explicitly check
              #   for `:example_group` here if it is one of the keys being used to
              #   filter.
              hash[key] = metadata[key] if metadata.key?(key) || key == :example_group
              hash
            end
          end
        end

        def proc_keys_from(metadata)
          metadata.each_with_object([]) do |(key, value), to_return|
            to_return << key if Proc === value
          end
        end

        unless [].respond_to?(:each_with_object) # For 1.8.7
          # :nocov:
          undef proc_keys_from
          def proc_keys_from(metadata)
            metadata.inject([]) do |to_return, (key, value)|
              to_return << key if Proc === value
              to_return
            end
          end
          # :nocov:
        end
      end
    end
  end
end
