module RSpec
  module Support
    module InSubProcess
      if Process.respond_to?(:fork) && !(Ruby.jruby? && RUBY_VERSION == '1.8.7')

        UnmarshableObject = Struct.new(:error)

        # Useful as a way to isolate a global change to a subprocess.

        # rubocop:disable MethodLength
        def in_sub_process(prevent_warnings=true)
          exception_reader, exception_writer = IO.pipe
          result_reader, result_writer = IO.pipe

          pid = Process.fork do
            warning_preventer = $stderr = RSpec::Support::StdErrSplitter.new($stderr)

            begin
              result = yield
              warning_preventer.verify_no_warnings! if prevent_warnings
              # rubocop:disable Lint/HandleExceptions
            rescue Support::AllExceptionsExceptOnesWeMustNotRescue => exception
              # rubocop:enable Lint/HandleExceptions
            end

            exception_writer.write marshal_dump_with_unmarshable_object_handling(exception)
            exception_reader.close
            exception_writer.close

            result_writer.write marshal_dump_with_unmarshable_object_handling(result)
            result_reader.close
            result_writer.close

            exit! # prevent at_exit hooks from running (e.g. minitest)
          end

          exception_writer.close
          result_writer.close
          Process.waitpid(pid)

          exception = Marshal.load(exception_reader.read)
          exception_reader.close
          raise exception if exception

          result = Marshal.load(result_reader.read)
          result_reader.close
          result
        end
        # rubocop:enable MethodLength
        alias :in_sub_process_if_possible :in_sub_process

        def marshal_dump_with_unmarshable_object_handling(object)
          Marshal.dump(object)
        rescue TypeError => error
          Marshal.dump(UnmarshableObject.new(error))
        end
      else
        def in_sub_process(*)
          skip "This spec requires forking to work properly, " \
               "and your platform does not support forking"
        end

        def in_sub_process_if_possible(*)
          yield
        end
      end
    end
  end
end
