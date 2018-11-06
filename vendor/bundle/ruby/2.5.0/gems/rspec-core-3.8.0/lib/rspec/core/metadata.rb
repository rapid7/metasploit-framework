module RSpec
  module Core
    # Each ExampleGroup class and Example instance owns an instance of
    # Metadata, which is Hash extended to support lazy evaluation of values
    # associated with keys that may or may not be used by any example or group.
    #
    # In addition to metadata that is used internally, this also stores
    # user-supplied metadata, e.g.
    #
    #     describe Something, :type => :ui do
    #       it "does something", :slow => true do
    #         # ...
    #       end
    #     end
    #
    # `:type => :ui` is stored in the Metadata owned by the example group, and
    # `:slow => true` is stored in the Metadata owned by the example. These can
    # then be used to select which examples are run using the `--tag` option on
    # the command line, or several methods on `Configuration` used to filter a
    # run (e.g. `filter_run_including`, `filter_run_excluding`, etc).
    #
    # @see Example#metadata
    # @see ExampleGroup.metadata
    # @see FilterManager
    # @see Configuration#filter_run_including
    # @see Configuration#filter_run_excluding
    module Metadata
      # Matches strings either at the beginning of the input or prefixed with a
      # whitespace, containing the current path, either postfixed with the
      # separator, or at the end of the string. Match groups are the character
      # before and the character after the string if any.
      #
      # http://rubular.com/r/fT0gmX6VJX
      # http://rubular.com/r/duOrD4i3wb
      # http://rubular.com/r/sbAMHFrOx1
      def self.relative_path_regex
        @relative_path_regex ||= /(\A|\s)#{File.expand_path('.')}(#{File::SEPARATOR}|\s|\Z)/
      end

      # @api private
      #
      # @param line [String] current code line
      # @return [String] relative path to line
      def self.relative_path(line)
        line = line.sub(relative_path_regex, "\\1.\\2".freeze)
        line = line.sub(/\A([^:]+:\d+)$/, '\\1'.freeze)
        return nil if line == '-e:1'.freeze
        line
      rescue SecurityError
        # :nocov:
        nil
        # :nocov:
      end

      # @private
      # Iteratively walks up from the given metadata through all
      # example group ancestors, yielding each metadata hash along the way.
      def self.ascending(metadata)
        yield metadata
        return unless (group_metadata = metadata.fetch(:example_group) { metadata[:parent_example_group] })

        loop do
          yield group_metadata
          break unless (group_metadata = group_metadata[:parent_example_group])
        end
      end

      # @private
      # Returns an enumerator that iteratively walks up the given metadata through all
      # example group ancestors, yielding each metadata hash along the way.
      def self.ascend(metadata)
        enum_for(:ascending, metadata)
      end

      # @private
      # Used internally to build a hash from an args array.
      # Symbols are converted into hash keys with a value of `true`.
      # This is done to support simple tagging using a symbol, rather
      # than needing to do `:symbol => true`.
      def self.build_hash_from(args, warn_about_example_group_filtering=false)
        hash = args.last.is_a?(Hash) ? args.pop : {}

        hash[args.pop] = true while args.last.is_a?(Symbol)

        if warn_about_example_group_filtering && hash.key?(:example_group)
          RSpec.deprecate("Filtering by an `:example_group` subhash",
                          :replacement => "the subhash to filter directly")
        end

        hash
      end

      # @private
      def self.deep_hash_dup(object)
        return object.dup if Array === object
        return object unless Hash  === object

        object.inject(object.dup) do |duplicate, (key, value)|
          duplicate[key] = deep_hash_dup(value)
          duplicate
        end
      end

      # @private
      def self.id_from(metadata)
        "#{metadata[:rerun_file_path]}[#{metadata[:scoped_id]}]"
      end

      # @private
      def self.location_tuple_from(metadata)
        [metadata[:absolute_file_path], metadata[:line_number]]
      end

      # @private
      # Used internally to populate metadata hashes with computed keys
      # managed by RSpec.
      class HashPopulator
        attr_reader :metadata, :user_metadata, :description_args, :block

        def initialize(metadata, user_metadata, index_provider, description_args, block)
          @metadata         = metadata
          @user_metadata    = user_metadata
          @index_provider   = index_provider
          @description_args = description_args
          @block            = block
        end

        def populate
          ensure_valid_user_keys

          metadata[:block]            = block
          metadata[:description_args] = description_args
          metadata[:description]      = build_description_from(*metadata[:description_args])
          metadata[:full_description] = full_description
          metadata[:described_class]  = described_class

          populate_location_attributes
          metadata.update(user_metadata)
          RSpec.configuration.apply_derived_metadata_to(metadata)
        end

      private

        def populate_location_attributes
          backtrace = user_metadata.delete(:caller)

          file_path, line_number = if backtrace
                                     file_path_and_line_number_from(backtrace)
                                   elsif block.respond_to?(:source_location)
                                     block.source_location
                                   else
                                     file_path_and_line_number_from(caller)
                                   end

          relative_file_path            = Metadata.relative_path(file_path)
          absolute_file_path            = File.expand_path(relative_file_path)
          metadata[:file_path]          = relative_file_path
          metadata[:line_number]        = line_number.to_i
          metadata[:location]           = "#{relative_file_path}:#{line_number}"
          metadata[:absolute_file_path] = absolute_file_path
          metadata[:rerun_file_path]  ||= relative_file_path
          metadata[:scoped_id]          = build_scoped_id_for(absolute_file_path)
        end

        def file_path_and_line_number_from(backtrace)
          first_caller_from_outside_rspec = backtrace.find { |l| l !~ CallerFilter::LIB_REGEX }
          first_caller_from_outside_rspec ||= backtrace.first
          /(.+?):(\d+)(?:|:\d+)/.match(first_caller_from_outside_rspec).captures
        end

        def description_separator(parent_part, child_part)
          if parent_part.is_a?(Module) && child_part =~ /^(#|::|\.)/
            ''.freeze
          else
            ' '.freeze
          end
        end

        def build_description_from(parent_description=nil, my_description=nil)
          return parent_description.to_s unless my_description
          return my_description.to_s if parent_description.to_s == ''
          separator = description_separator(parent_description, my_description)
          (parent_description.to_s + separator) << my_description.to_s
        end

        def build_scoped_id_for(file_path)
          index = @index_provider.call(file_path).to_s
          parent_scoped_id = metadata.fetch(:scoped_id) { return index }
          "#{parent_scoped_id}:#{index}"
        end

        def ensure_valid_user_keys
          RESERVED_KEYS.each do |key|
            next unless user_metadata.key?(key)
            raise <<-EOM.gsub(/^\s+\|/, '')
              |#{"*" * 50}
              |:#{key} is not allowed
              |
              |RSpec reserves some hash keys for its own internal use,
              |including :#{key}, which is used on:
              |
              |  #{CallerFilter.first_non_rspec_line}.
              |
              |Here are all of RSpec's reserved hash keys:
              |
              |  #{RESERVED_KEYS.join("\n  ")}
              |#{"*" * 50}
            EOM
          end
        end
      end

      # @private
      class ExampleHash < HashPopulator
        def self.create(group_metadata, user_metadata, index_provider, description, block)
          example_metadata = group_metadata.dup
          group_metadata = Hash.new(&ExampleGroupHash.backwards_compatibility_default_proc do |hash|
            hash[:parent_example_group]
          end)
          group_metadata.update(example_metadata)

          example_metadata[:execution_result] = Example::ExecutionResult.new
          example_metadata[:example_group] = group_metadata
          example_metadata[:shared_group_inclusion_backtrace] = SharedExampleGroupInclusionStackFrame.current_backtrace
          example_metadata.delete(:parent_example_group)

          description_args = description.nil? ? [] : [description]
          hash = new(example_metadata, user_metadata, index_provider, description_args, block)
          hash.populate
          hash.metadata
        end

      private

        def described_class
          metadata[:example_group][:described_class]
        end

        def full_description
          build_description_from(
            metadata[:example_group][:full_description],
            metadata[:description]
          )
        end
      end

      # @private
      class ExampleGroupHash < HashPopulator
        def self.create(parent_group_metadata, user_metadata, example_group_index, *args, &block)
          group_metadata = hash_with_backwards_compatibility_default_proc

          if parent_group_metadata
            group_metadata.update(parent_group_metadata)
            group_metadata[:parent_example_group] = parent_group_metadata
          end

          hash = new(group_metadata, user_metadata, example_group_index, args, block)
          hash.populate
          hash.metadata
        end

        def self.hash_with_backwards_compatibility_default_proc
          Hash.new(&backwards_compatibility_default_proc { |hash| hash })
        end

        def self.backwards_compatibility_default_proc(&example_group_selector)
          Proc.new do |hash, key|
            case key
            when :example_group
              # We commonly get here when rspec-core is applying a previously
              # configured filter rule, such as when a gem configures:
              #
              #   RSpec.configure do |c|
              #     c.include MyGemHelpers, :example_group => { :file_path => /spec\/my_gem_specs/ }
              #   end
              #
              # It's confusing for a user to get a deprecation at this point in
              # the code, so instead we issue a deprecation from the config APIs
              # that take a metadata hash, and MetadataFilter sets this thread
              # local to silence the warning here since it would be so
              # confusing.
              unless RSpec::Support.thread_local_data[:silence_metadata_example_group_deprecations]
                RSpec.deprecate("The `:example_group` key in an example group's metadata hash",
                                :replacement => "the example group's hash directly for the " \
                                "computed keys and `:parent_example_group` to access the parent " \
                                "example group metadata")
              end

              group_hash = example_group_selector.call(hash)
              LegacyExampleGroupHash.new(group_hash) if group_hash
            when :example_group_block
              RSpec.deprecate("`metadata[:example_group_block]`",
                              :replacement => "`metadata[:block]`")
              hash[:block]
            when :describes
              RSpec.deprecate("`metadata[:describes]`",
                              :replacement => "`metadata[:described_class]`")
              hash[:described_class]
            end
          end
        end

      private

        def described_class
          candidate = metadata[:description_args].first
          return candidate unless NilClass === candidate || String === candidate
          parent_group = metadata[:parent_example_group]
          parent_group && parent_group[:described_class]
        end

        def full_description
          description          = metadata[:description]
          parent_example_group = metadata[:parent_example_group]
          return description unless parent_example_group

          parent_description   = parent_example_group[:full_description]
          separator = description_separator(parent_example_group[:description_args].last,
                                            metadata[:description_args].first)

          parent_description + separator + description
        end
      end

      # @private
      RESERVED_KEYS = [
        :description,
        :description_args,
        :described_class,
        :example_group,
        :parent_example_group,
        :execution_result,
        :last_run_status,
        :file_path,
        :absolute_file_path,
        :rerun_file_path,
        :full_description,
        :line_number,
        :location,
        :scoped_id,
        :block,
        :shared_group_inclusion_backtrace
      ]
    end

    # Mixin that makes the including class imitate a hash for backwards
    # compatibility. The including class should use `attr_accessor` to
    # declare attributes.
    # @private
    module HashImitatable
      def self.included(klass)
        klass.extend ClassMethods
      end

      def to_h
        hash = extra_hash_attributes.dup

        self.class.hash_attribute_names.each do |name|
          hash[name] = __send__(name)
        end

        hash
      end

      (Hash.public_instance_methods - Object.public_instance_methods).each do |method_name|
        next if [:[], :[]=, :to_h].include?(method_name.to_sym)

        define_method(method_name) do |*args, &block|
          issue_deprecation(method_name, *args)

          hash = hash_for_delegation
          self.class.hash_attribute_names.each do |name|
            hash.delete(name) unless instance_variable_defined?(:"@#{name}")
          end

          hash.__send__(method_name, *args, &block).tap do
            # apply mutations back to the object
            hash.each do |name, value|
              if directly_supports_attribute?(name)
                set_value(name, value)
              else
                extra_hash_attributes[name] = value
              end
            end
          end
        end
      end

      def [](key)
        issue_deprecation(:[], key)

        if directly_supports_attribute?(key)
          get_value(key)
        else
          extra_hash_attributes[key]
        end
      end

      def []=(key, value)
        issue_deprecation(:[]=, key, value)

        if directly_supports_attribute?(key)
          set_value(key, value)
        else
          extra_hash_attributes[key] = value
        end
      end

    private

      def extra_hash_attributes
        @extra_hash_attributes ||= {}
      end

      def directly_supports_attribute?(name)
        self.class.hash_attribute_names.include?(name)
      end

      def get_value(name)
        __send__(name)
      end

      def set_value(name, value)
        __send__(:"#{name}=", value)
      end

      def hash_for_delegation
        to_h
      end

      def issue_deprecation(_method_name, *_args)
        # no-op by default: subclasses can override
      end

      # @private
      module ClassMethods
        def hash_attribute_names
          @hash_attribute_names ||= []
        end

        def attr_accessor(*names)
          hash_attribute_names.concat(names)
          super
        end
      end
    end

    # @private
    # Together with the example group metadata hash default block,
    # provides backwards compatibility for the old `:example_group`
    # key. In RSpec 2.x, the computed keys of a group's metadata
    # were exposed from a nested subhash keyed by `[:example_group]`, and
    # then the parent group's metadata was exposed by sub-subhash
    # keyed by `[:example_group][:example_group]`.
    #
    # In RSpec 3, we reorganized this to that the computed keys are
    # exposed directly of the group metadata hash (no nesting), and
    # `:parent_example_group` returns the parent group's metadata.
    #
    # Maintaining backwards compatibility was difficult: we wanted
    # `:example_group` to return an object that:
    #
    #   * Exposes the top-level metadata keys that used to be nested
    #     under `:example_group`.
    #   * Supports mutation (rspec-rails, for example, assigns
    #     `metadata[:example_group][:described_class]` when you use
    #     anonymous controller specs) such that changes are written
    #     back to the top-level metadata hash.
    #   * Exposes the parent group metadata as
    #     `[:example_group][:example_group]`.
    class LegacyExampleGroupHash
      include HashImitatable

      def initialize(metadata)
        @metadata = metadata
        parent_group_metadata = metadata.fetch(:parent_example_group) { {} }[:example_group]
        self[:example_group] = parent_group_metadata if parent_group_metadata
      end

      def to_h
        super.merge(@metadata)
      end

    private

      def directly_supports_attribute?(name)
        name != :example_group
      end

      def get_value(name)
        @metadata[name]
      end

      def set_value(name, value)
        @metadata[name] = value
      end
    end
  end
end
