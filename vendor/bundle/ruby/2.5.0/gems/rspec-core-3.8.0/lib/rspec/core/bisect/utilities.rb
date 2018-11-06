module RSpec
  module Core
    module Bisect
      # @private
      ExampleSetDescriptor = Struct.new(:all_example_ids, :failed_example_ids)

      # @private
      class BisectFailedError < StandardError
        def self.for_failed_spec_run(spec_output)
          new("Failed to get results from the spec run. Spec run output:\n\n" +
              spec_output)
        end
      end

      # Wraps a `formatter` providing a simple means to notify it in place
      # of an `RSpec::Core::Reporter`, without involving configuration in
      # any way.
      # @private
      class Notifier
        def initialize(formatter)
          @formatter = formatter
        end

        def publish(event, *args)
          return unless @formatter.respond_to?(event)
          notification = Notifications::CustomNotification.for(*args)
          @formatter.__send__(event, notification)
        end
      end

      # Wraps a pipe to support sending objects between a child and
      # parent process.
      # @private
      class Channel
        def initialize
          @read_io, @write_io = IO.pipe
        end

        def send(message)
          packet = Marshal.dump(message)
          @write_io.write("#{packet.bytesize}\n#{packet}")
        end

        # rubocop:disable Security/MarshalLoad
        def receive
          packet_size = Integer(@read_io.gets)
          Marshal.load(@read_io.read(packet_size))
        end
        # rubocop:enable Security/MarshalLoad

        def close
          @read_io.close
          @write_io.close
        end
      end
    end
  end
end
