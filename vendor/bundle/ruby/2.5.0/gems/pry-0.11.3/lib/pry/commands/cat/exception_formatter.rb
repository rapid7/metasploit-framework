class Pry
  class Command::Cat
    class ExceptionFormatter < AbstractFormatter
      attr_reader :ex
      attr_reader :opts
      attr_reader :_pry_

      def initialize(exception, _pry_, opts)
        @ex = exception
        @opts = opts
        @_pry_ = _pry_
      end

      def format
        check_for_errors
        set_file_and_dir_locals(backtrace_file, _pry_, _pry_.current_context)
        code = decorate(Pry::Code.from_file(backtrace_file).
                                    between(*start_and_end_line_for_code_window).
                                    with_marker(backtrace_line))
        "#{header}#{code}"
      end

      private

      def code_window_size
        _pry_.config.default_window_size || 5
      end

      def backtrace_level
        @backtrace_level ||=
          begin
            bl =  if opts[:ex].nil?
                    ex.bt_index
                  else
                    ex.bt_index = absolute_index_number(opts[:ex], ex.backtrace.size)
                  end

            increment_backtrace_level
            bl
          end
      end

      def increment_backtrace_level
        ex.inc_bt_index
      end

      def backtrace_file
        Array(ex.bt_source_location_for(backtrace_level)).first
      end

      def backtrace_line
        Array(ex.bt_source_location_for(backtrace_level)).last
      end

      def check_for_errors
        raise CommandError, "No exception found." unless ex
        raise CommandError, "The given backtrace level is out of bounds." unless backtrace_file
      end

      def start_and_end_line_for_code_window
        start_line = backtrace_line - code_window_size
        start_line = 1 if start_line < 1

        [start_line, backtrace_line + code_window_size]
      end

      def header
        unindent %{
        #{Helpers::Text.bold 'Exception:'} #{ex.class}: #{ex.message}
        --
        #{Helpers::Text.bold('From:')} #{backtrace_file} @ line #{backtrace_line} @ #{Helpers::Text.bold("level: #{backtrace_level}")} of backtrace (of #{ex.backtrace.size - 1}).

      }
      end

    end
  end
end
