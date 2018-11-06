module RSpec
  module Core
    # @api private
    #
    # Internal container for global non-configuration data.
    class World
      # @private
      attr_reader :example_groups, :filtered_examples

      # Used internally to determine what to do when a SIGINT is received.
      attr_accessor :wants_to_quit

      # Used internally to signal that a failure outside of an example
      # has occurred, and that therefore the exit status should indicate
      # the run failed.
      # @private
      attr_accessor :non_example_failure

      def initialize(configuration=RSpec.configuration)
        @configuration = configuration
        configuration.world = self
        @example_groups = []
        @example_group_counts_by_spec_file = Hash.new(0)
        prepare_example_filtering
      end

      # @api public
      #
      # Prepares filters so that they apply to example groups when they run.
      #
      # This is a separate method so that filters can be modified/replaced and
      # examples refiltered during a process's lifetime, which can be useful for
      # a custom runner.
      def prepare_example_filtering
        @filtered_examples = Hash.new do |hash, group|
          hash[group] = filter_manager.prune(group.examples)
        end
      end

      # @api private
      #
      # Apply ordering strategy from configuration to example groups.
      def ordered_example_groups
        ordering_strategy = @configuration.ordering_registry.fetch(:global)
        ordering_strategy.order(@example_groups)
      end

      # @api private
      #
      # Reset world to 'scratch' before running suite.
      def reset
        RSpec::ExampleGroups.remove_all_constants
        example_groups.clear
        @sources_by_path.clear if defined?(@sources_by_path)
        @syntax_highlighter = nil
      end

      # @private
      def filter_manager
        @configuration.filter_manager
      end

      # @private
      def registered_example_group_files
        @example_group_counts_by_spec_file.keys
      end

      # @api private
      #
      # Records an example group.
      def record(example_group)
        @configuration.on_example_group_definition_callbacks.each { |block| block.call(example_group) }
        @example_group_counts_by_spec_file[example_group.metadata[:absolute_file_path]] += 1
      end

      # @private
      def num_example_groups_defined_in(file)
        @example_group_counts_by_spec_file[file]
      end

      # @private
      def shared_example_group_registry
        @shared_example_group_registry ||= SharedExampleGroup::Registry.new
      end

      # @private
      def inclusion_filter
        @configuration.inclusion_filter
      end

      # @private
      def exclusion_filter
        @configuration.exclusion_filter
      end

      # @api private
      #
      # Get count of examples to be run.
      def example_count(groups=example_groups)
        FlatMap.flat_map(groups) { |g| g.descendants }.
          inject(0) { |a, e| a + e.filtered_examples.size }
      end

      # @private
      def all_example_groups
        FlatMap.flat_map(example_groups) { |g| g.descendants }
      end

      # @private
      def all_examples
        FlatMap.flat_map(all_example_groups) { |g| g.examples }
      end

      # @private
      # Traverses the tree of each top level group.
      # For each it yields the group, then the children, recursively.
      # Halts the traversal of a branch of the tree as soon as the passed block returns true.
      # Note that siblings groups and their sub-trees will continue to be explored.
      # This is intended to make it easy to find the top-most group that satisfies some
      # condition.
      def traverse_example_group_trees_until(&block)
        example_groups.each do |group|
          group.traverse_tree_until(&block)
        end
      end

      # @api private
      #
      # Find line number of previous declaration.
      def preceding_declaration_line(absolute_file_name, filter_line)
        line_numbers = descending_declaration_line_numbers_by_file.fetch(absolute_file_name) do
          return nil
        end

        line_numbers.find { |num| num <= filter_line }
      end

      # @private
      def reporter
        @configuration.reporter
      end

      # @private
      def source_from_file(path)
        unless defined?(@sources_by_path)
          RSpec::Support.require_rspec_support 'source'
          @sources_by_path = {}
        end

        @sources_by_path[path] ||= Support::Source.from_file(path)
      end

      # @private
      def syntax_highlighter
        @syntax_highlighter ||= Formatters::SyntaxHighlighter.new(@configuration)
      end

      # @api private
      #
      # Notify reporter of filters.
      def announce_filters
        fail_if_config_and_cli_options_invalid
        filter_announcements = []

        announce_inclusion_filter filter_announcements
        announce_exclusion_filter filter_announcements

        unless filter_manager.empty?
          if filter_announcements.length == 1
            report_filter_message("Run options: #{filter_announcements[0]}")
          else
            report_filter_message("Run options:\n  #{filter_announcements.join("\n  ")}")
          end
        end

        if @configuration.run_all_when_everything_filtered? && example_count.zero? && !@configuration.only_failures?
          report_filter_message("#{everything_filtered_message}; ignoring #{inclusion_filter.description}")
          filtered_examples.clear
          inclusion_filter.clear
        end

        return unless example_count.zero?

        example_groups.clear
        if filter_manager.empty?
          report_filter_message("No examples found.")
        elsif exclusion_filter.empty? || inclusion_filter.empty?
          report_filter_message(everything_filtered_message)
        end
      end

      # @private
      def report_filter_message(message)
        reporter.message(message) unless @configuration.silence_filter_announcements?
      end

      # @private
      def everything_filtered_message
        "\nAll examples were filtered out"
      end

      # @api private
      #
      # Add inclusion filters to announcement message.
      def announce_inclusion_filter(announcements)
        return if inclusion_filter.empty?

        announcements << "include #{inclusion_filter.description}"
      end

      # @api private
      #
      # Add exclusion filters to announcement message.
      def announce_exclusion_filter(announcements)
        return if exclusion_filter.empty?

        announcements << "exclude #{exclusion_filter.description}"
      end

    private

      def descending_declaration_line_numbers_by_file
        @descending_declaration_line_numbers_by_file ||= begin
          declaration_locations = FlatMap.flat_map(example_groups, &:declaration_locations)
          hash_of_arrays = Hash.new { |h, k| h[k] = [] }

          # TODO: change `inject` to `each_with_object` when we drop 1.8.7 support.
          line_nums_by_file = declaration_locations.inject(hash_of_arrays) do |hash, (file_name, line_number)|
            hash[file_name] << line_number
            hash
          end

          line_nums_by_file.each_value do |list|
            list.sort!
            list.reverse!
          end
        end
      end

      def fail_if_config_and_cli_options_invalid
        return unless @configuration.only_failures_but_not_configured?

        reporter.abort_with(
          "\nTo use `--only-failures`, you must first set " \
          "`config.example_status_persistence_file_path`.",
          1 # exit code
        )
      end

      # @private
      # Provides a null implementation for initial use by configuration.
      module Null
        def self.non_example_failure; end
        def self.non_example_failure=(_); end

        def self.registered_example_group_files
          []
        end

        def self.traverse_example_group_trees_until
        end

        # :nocov:
        def self.example_groups
          []
        end

        def self.all_example_groups
          []
        end
        # :nocov:
      end
    end
  end
end
