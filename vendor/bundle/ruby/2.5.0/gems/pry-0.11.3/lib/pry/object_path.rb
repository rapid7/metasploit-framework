class Pry
  # `ObjectPath` implements the resolution of "object paths", which are strings
  # that are similar to filesystem paths but meant for traversing Ruby objects.
  # Examples of valid object paths include:
  #
  #     x
  #     @foo/@bar
  #     "string"/upcase
  #     Pry/Method
  #
  # Object paths are mostly relevant in the context of the `cd` command.
  # @see https://github.com/pry/pry/wiki/State-navigation
  class ObjectPath
    SPECIAL_TERMS = ["", "::", ".", ".."]

    # @param [String] path_string The object path expressed as a string.
    # @param [Array<Binding>] current_stack The current state of the binding
    #   stack.
    def initialize(path_string, current_stack)
      @path_string   = path_string
      @current_stack = current_stack
    end

    # @return [Array<Binding>] a new stack resulting from applying the given
    #   path to the current stack.
    def resolve
      scanner = StringScanner.new(@path_string.strip)
      stack   = @current_stack.dup

      begin
        next_segment  = ""

        loop do
          # Scan for as long as we don't see a slash
          next_segment << scanner.scan(/[^\/]*/)

          if complete?(next_segment) || scanner.eos?
            scanner.getch # consume the slash
            break
          else
            next_segment << scanner.getch # append the slash
          end
        end

        case next_segment.chomp
        when ""
          stack = [stack.first]
        when "::"
          stack.push(TOPLEVEL_BINDING)
        when "."
          next
        when ".."
          stack.pop unless stack.size == 1
        else
          stack.push(Pry.binding_for(stack.last.eval(next_segment)))
        end
      rescue RescuableException => e
        return handle_failure(next_segment, e)
      end until scanner.eos?

      stack
    end

    private

    def complete?(segment)
      SPECIAL_TERMS.include?(segment) || Pry::Code.complete_expression?(segment)
    end

    def handle_failure(context, err)
      msg = [
        "Bad object path: #{@path_string.inspect}",
        "Failed trying to resolve: #{context.inspect}",
        "Exception: #{err.inspect}"
      ].join("\n")

      raise CommandError.new(msg).tap { |e|
        e.set_backtrace err.backtrace
      }
    end
  end
end
