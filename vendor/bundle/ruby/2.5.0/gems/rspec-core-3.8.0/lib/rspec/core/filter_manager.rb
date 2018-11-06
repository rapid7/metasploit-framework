module RSpec
  module Core
    # @private
    class FilterManager
      attr_reader :exclusions, :inclusions

      def initialize
        @exclusions, @inclusions = FilterRules.build
      end

      # @api private
      #
      # @param file_path [String]
      # @param line_numbers [Array]
      def add_location(file_path, line_numbers)
        # locations is a hash of expanded paths to arrays of line
        # numbers to match against. e.g.
        #   { "path/to/file.rb" => [37, 42] }
        add_path_to_arrays_filter(:locations, File.expand_path(file_path), line_numbers)
      end

      def add_ids(rerun_path, scoped_ids)
        # ids is a hash of relative paths to arrays of ids
        # to match against. e.g.
        #   { "./path/to/file.rb" => ["1:1", "2:4"] }
        rerun_path = Metadata.relative_path(File.expand_path rerun_path)
        add_path_to_arrays_filter(:ids, rerun_path, scoped_ids)
      end

      def empty?
        inclusions.empty? && exclusions.empty?
      end

      def prune(examples)
        # Semantically, this is unnecessary (the filtering below will return the empty
        # array unmodified), but for perf reasons it's worth exiting early here. Users
        # commonly have top-level examples groups that do not have any direct examples
        # and instead have nested groups with examples. In that kind of situation,
        # `examples` will be empty.
        return examples if examples.empty?

        examples = prune_conditionally_filtered_examples(examples)

        if inclusions.standalone?
          examples.select { |e| inclusions.include_example?(e) }
        else
          locations, ids, non_scoped_inclusions = inclusions.split_file_scoped_rules

          examples.select do |ex|
            file_scoped_include?(ex.metadata, ids, locations) do
              !exclusions.include_example?(ex) && non_scoped_inclusions.include_example?(ex)
            end
          end
        end
      end

      def exclude(*args)
        exclusions.add(args.last)
      end

      def exclude_only(*args)
        exclusions.use_only(args.last)
      end

      def exclude_with_low_priority(*args)
        exclusions.add_with_low_priority(args.last)
      end

      def include(*args)
        inclusions.add(args.last)
      end

      def include_only(*args)
        inclusions.use_only(args.last)
      end

      def include_with_low_priority(*args)
        inclusions.add_with_low_priority(args.last)
      end

    private

      def add_path_to_arrays_filter(filter_key, path, values)
        filter = inclusions.delete(filter_key) || Hash.new { |h, k| h[k] = [] }
        filter[path].concat(values)
        inclusions.add(filter_key => filter)
      end

      def prune_conditionally_filtered_examples(examples)
        examples.reject do |ex|
          meta = ex.metadata
          !meta.fetch(:if, true) || meta[:unless]
        end
      end

      # When a user specifies a particular spec location, that takes priority
      # over any exclusion filters (such as if the spec is tagged with `:slow`
      # and there is a `:slow => true` exclusion filter), but only for specs
      # defined in the same file as the location filters. Excluded specs in
      # other files should still be excluded.
      def file_scoped_include?(ex_metadata, ids, locations)
        no_id_filters = ids[ex_metadata[:rerun_file_path]].empty?
        no_location_filters = locations[
          File.expand_path(ex_metadata[:rerun_file_path])
        ].empty?

        return yield if no_location_filters && no_id_filters

        MetadataFilter.filter_applies?(:ids, ids, ex_metadata) ||
        MetadataFilter.filter_applies?(:locations, locations, ex_metadata)
      end
    end

    # @private
    class FilterRules
      PROC_HEX_NUMBER = /0x[0-9a-f]+@/
      PROJECT_DIR = File.expand_path('.')

      attr_accessor :opposite
      attr_reader :rules

      def self.build
        exclusions = ExclusionRules.new
        inclusions = InclusionRules.new
        exclusions.opposite = inclusions
        inclusions.opposite = exclusions
        [exclusions, inclusions]
      end

      def initialize(rules={})
        @rules = rules
      end

      def add(updated)
        @rules.merge!(updated).each_key { |k| opposite.delete(k) }
      end

      def add_with_low_priority(updated)
        updated = updated.merge(@rules)
        opposite.each_pair { |k, v| updated.delete(k) if updated[k] == v }
        @rules.replace(updated)
      end

      def use_only(updated)
        updated.each_key { |k| opposite.delete(k) }
        @rules.replace(updated)
      end

      def clear
        @rules.clear
      end

      def delete(key)
        @rules.delete(key)
      end

      def fetch(*args, &block)
        @rules.fetch(*args, &block)
      end

      def [](key)
        @rules[key]
      end

      def empty?
        rules.empty?
      end

      def each_pair(&block)
        @rules.each_pair(&block)
      end

      def description
        rules.inspect.gsub(PROC_HEX_NUMBER, '').gsub(PROJECT_DIR, '.').gsub(' (lambda)', '')
      end

      def include_example?(example)
        MetadataFilter.apply?(:any?, @rules, example.metadata)
      end
    end

    # @private
    ExclusionRules = FilterRules

    # @private
    class InclusionRules < FilterRules
      def add(*args)
        apply_standalone_filter(*args) || super
      end

      def add_with_low_priority(*args)
        apply_standalone_filter(*args) || super
      end

      def include_example?(example)
        @rules.empty? || super
      end

      def standalone?
        is_standalone_filter?(@rules)
      end

      def split_file_scoped_rules
        rules_dup = @rules.dup
        locations = rules_dup.delete(:locations) { Hash.new([]) }
        ids       = rules_dup.delete(:ids)       { Hash.new([]) }

        return locations, ids, self.class.new(rules_dup)
      end

    private

      def apply_standalone_filter(updated)
        return true if standalone?
        return nil unless is_standalone_filter?(updated)

        replace_filters(updated)
        true
      end

      def replace_filters(new_rules)
        @rules.replace(new_rules)
        opposite.clear
      end

      def is_standalone_filter?(rules)
        rules.key?(:full_description)
      end
    end
  end
end
