module RSpec
  module Core
    # Represents some functionality that is shared with multiple example groups.
    # The functionality is defined by the provided block, which is lazily
    # eval'd when the `SharedExampleGroupModule` instance is included in an example
    # group.
    class SharedExampleGroupModule < Module
      # @private
      attr_reader :definition

      def initialize(description, definition, metadata)
        @description = description
        @definition  = definition
        @metadata    = metadata
      end

      # Provides a human-readable representation of this module.
      def inspect
        "#<#{self.class.name} #{@description.inspect}>"
      end
      alias to_s inspect

      # Ruby callback for when a module is included in another module is class.
      # Our definition evaluates the shared group block in the context of the
      # including example group.
      def included(klass)
        inclusion_line = klass.metadata[:location]
        include_in klass, inclusion_line, [], nil
      end

      # @private
      def include_in(klass, inclusion_line, args, customization_block)
        klass.update_inherited_metadata(@metadata) unless @metadata.empty?

        SharedExampleGroupInclusionStackFrame.with_frame(@description, inclusion_line) do
          klass.class_exec(*args, &@definition)
          klass.class_exec(&customization_block) if customization_block
        end
      end
    end

    # Shared example groups let you define common context and/or common
    # examples that you wish to use in multiple example groups.
    #
    # When defined, the shared group block is stored for later evaluation.
    # It can later be included in an example group either explicitly
    # (using `include_examples`, `include_context` or `it_behaves_like`)
    # or implicitly (via matching metadata).
    #
    # Named shared example groups are scoped based on where they are
    # defined. Shared groups defined in an example group are available
    # for inclusion in that example group or any child example groups,
    # but not in any parent or sibling example groups. Shared example
    # groups defined at the top level can be included from any example group.
    module SharedExampleGroup
      # @overload shared_examples(name, &block)
      #   @param name [String, Symbol, Module] identifer to use when looking up
      #     this shared group
      #   @param block The block to be eval'd
      # @overload shared_examples(name, metadata, &block)
      #   @param name [String, Symbol, Module] identifer to use when looking up
      #     this shared group
      #   @param metadata [Array<Symbol>, Hash] metadata to attach to this
      #     group; any example group or example with matching metadata will
      #     automatically include this shared example group.
      #   @param block The block to be eval'd
      #
      # Stores the block for later use. The block will be evaluated
      # in the context of an example group via `include_examples`,
      # `include_context`, or `it_behaves_like`.
      #
      # @example
      #   shared_examples "auditable" do
      #     it "stores an audit record on save!" do
      #       expect { auditable.save! }.to change(Audit, :count).by(1)
      #     end
      #   end
      #
      #   describe Account do
      #     it_behaves_like "auditable" do
      #       let(:auditable) { Account.new }
      #     end
      #   end
      #
      # @see ExampleGroup.it_behaves_like
      # @see ExampleGroup.include_examples
      # @see ExampleGroup.include_context
      def shared_examples(name, *args, &block)
        top_level = self == ExampleGroup
        if top_level && RSpec::Support.thread_local_data[:in_example_group]
          raise "Creating isolated shared examples from within a context is " \
                "not allowed. Remove `RSpec.` prefix or move this to a " \
                "top-level scope."
        end

        RSpec.world.shared_example_group_registry.add(self, name, *args, &block)
      end
      alias shared_context      shared_examples
      alias shared_examples_for shared_examples

      # @api private
      #
      # Shared examples top level DSL.
      module TopLevelDSL
        # @private
        def self.definitions
          proc do
            def shared_examples(name, *args, &block)
              RSpec.world.shared_example_group_registry.add(:main, name, *args, &block)
            end
            alias shared_context      shared_examples
            alias shared_examples_for shared_examples
          end
        end

        # @private
        def self.exposed_globally?
          @exposed_globally ||= false
        end

        # @api private
        #
        # Adds the top level DSL methods to Module and the top level binding.
        def self.expose_globally!
          return if exposed_globally?
          Core::DSL.change_global_dsl(&definitions)
          @exposed_globally = true
        end

        # @api private
        #
        # Removes the top level DSL methods to Module and the top level binding.
        def self.remove_globally!
          return unless exposed_globally?

          Core::DSL.change_global_dsl do
            undef shared_examples
            undef shared_context
            undef shared_examples_for
          end

          @exposed_globally = false
        end
      end

      # @private
      class Registry
        def add(context, name, *metadata_args, &block)
          unless block
            RSpec.warning "Shared example group #{name} was defined without a "\
                          "block and will have no effect. Please define a "\
                          "block or remove the definition."
          end

          if RSpec.configuration.shared_context_metadata_behavior == :trigger_inclusion
            return legacy_add(context, name, *metadata_args, &block)
          end

          unless valid_name?(name)
            raise ArgumentError, "Shared example group names can only be a string, " \
                                 "symbol or module but got: #{name.inspect}"
          end

          ensure_block_has_source_location(block) { CallerFilter.first_non_rspec_line }
          warn_if_key_taken context, name, block

          metadata = Metadata.build_hash_from(metadata_args)
          shared_module = SharedExampleGroupModule.new(name, block, metadata)
          shared_example_groups[context][name] = shared_module
        end

        def find(lookup_contexts, name)
          lookup_contexts.each do |context|
            found = shared_example_groups[context][name]
            return found if found
          end

          shared_example_groups[:main][name]
        end

      private

        # TODO: remove this in RSpec 4. This exists only to support
        # `config.shared_context_metadata_behavior == :trigger_inclusion`,
        # the legacy behavior of shared context metadata, which we do
        # not want to support in RSpec 4.
        def legacy_add(context, name, *metadata_args, &block)
          ensure_block_has_source_location(block) { CallerFilter.first_non_rspec_line }
          shared_module = SharedExampleGroupModule.new(name, block, {})

          if valid_name?(name)
            warn_if_key_taken context, name, block
            shared_example_groups[context][name] = shared_module
          else
            metadata_args.unshift name
          end

          return if metadata_args.empty?
          RSpec.configuration.include shared_module, *metadata_args
        end

        def shared_example_groups
          @shared_example_groups ||= Hash.new { |hash, context| hash[context] = {} }
        end

        def valid_name?(candidate)
          case candidate
          when String, Symbol, Module then true
          else false
          end
        end

        def warn_if_key_taken(context, key, new_block)
          existing_module = shared_example_groups[context][key]
          return unless existing_module

          old_definition_location = formatted_location existing_module.definition
          new_definition_location = formatted_location new_block
          loaded_spec_files = RSpec.configuration.loaded_spec_files

          if loaded_spec_files.include?(new_definition_location) && old_definition_location == new_definition_location
            RSpec.warn_with <<-WARNING.gsub(/^ +\|/, ''), :call_site => nil
              |WARNING: Your shared example group, '#{key}', defined at:
              | #{old_definition_location}
              |was automatically loaded by RSpec because the file name
              |matches the configured autoloading pattern (#{RSpec.configuration.pattern}),
              |and is also being required from somewhere else. To fix this
              |warning, either rename the file to not match the pattern, or
              |do not explicitly require the file.
            WARNING
          else
            RSpec.warn_with <<-WARNING.gsub(/^ +\|/, ''), :call_site => nil
              |WARNING: Shared example group '#{key}' has been previously defined at:
              |  #{old_definition_location}
              |...and you are now defining it at:
              |  #{new_definition_location}
              |The new definition will overwrite the original one.
            WARNING
          end
        end

        if RUBY_VERSION.to_f >= 1.9
          def formatted_location(block)
            block.source_location.join(":")
          end
        else # 1.8.7
          # :nocov:
          def formatted_location(block)
            block.source_location.join(":").gsub(/:in.*$/, '')
          end
          # :nocov:
        end

        if Proc.method_defined?(:source_location)
          def ensure_block_has_source_location(_block); end
        else # for 1.8.7
          # :nocov:
          def ensure_block_has_source_location(block)
            source_location = yield.split(':')
            block.extend(Module.new { define_method(:source_location) { source_location } })
          end
          # :nocov:
        end
      end
    end
  end

  instance_exec(&Core::SharedExampleGroup::TopLevelDSL.definitions)
end
