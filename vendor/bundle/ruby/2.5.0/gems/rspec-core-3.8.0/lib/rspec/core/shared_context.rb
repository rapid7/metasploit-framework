module RSpec
  module Core
    # Exposes {ExampleGroup}-level methods to a module, so you can include that
    # module in an {ExampleGroup}.
    #
    # @example
    #
    #     module LoggedInAsAdmin
    #       extend RSpec::Core::SharedContext
    #       before(:example) do
    #         log_in_as :admin
    #       end
    #     end
    #
    #     describe "admin section" do
    #       include LoggedInAsAdmin
    #       # ...
    #     end
    module SharedContext
      # @private
      def included(group)
        __shared_context_recordings.each do |recording|
          recording.playback_onto(group)
        end
      end

      # @private
      def __shared_context_recordings
        @__shared_context_recordings ||= []
      end

      # @private
      Recording = Struct.new(:method_name, :args, :block) do
        def playback_onto(group)
          group.__send__(method_name, *args, &block)
        end
      end

      # @private
      def self.record(methods)
        methods.each do |meth|
          define_method(meth) do |*args, &block|
            __shared_context_recordings << Recording.new(meth, args, block)
          end
        end
      end

      # @private
      record [:describe, :context] + Hooks.instance_methods(false) +
        MemoizedHelpers::ClassMethods.instance_methods(false)
    end
  end
  # @private
  SharedContext = Core::SharedContext
end
