class Pry
  class Command::AmendLine < Pry::ClassCommand
    match(/amend-line(?: (-?\d+)(?:\.\.(-?\d+))?)?/)
    group 'Editing'
    description 'Amend a line of input in multi-line mode.'
    command_options :interpolate => false, :listing => 'amend-line'

    banner <<-'BANNER'
      Amend a line of input in multi-line mode. `amend-line N`, where the N represents
      line to replace. Can also specify a range of lines using `amend-line N..M`
      syntax. Passing "!" as replacement content deletes the line(s) instead.

      amend-line 1 puts 'new'    # replace line 1
      amend-line 1..4 !          # delete lines 1..4
      amend-line 3 >puts 'bye'   # insert before line 3
      amend-line puts 'appended' # no line number modifies immediately preceding line
    BANNER

    def process
      raise CommandError, "No input to amend." if eval_string.empty?

      eval_string.replace amended_input(eval_string)
      run "fix-indent"
      run "show-input"
    end

    private

    # @param [String] string The string to amend.
    # @return [String] A new string with the amendments applied to it.
    def amended_input(string)
      input_array = eval_string.each_line.to_a

      if arg_string == "!"
        delete_from_array(input_array, line_range)
      elsif arg_string.start_with?(">")
        insert_into_array(input_array, line_range)
      else
        replace_in_array(input_array, line_range)
      end

      input_array.join
    end

    def delete_from_array(array, range)
      array.slice!(range)
    end

    def insert_into_array(array, range)
      insert_slot = Array(range).first
      array.insert(insert_slot, arg_string[1..-1] << "\n")
    end

    def replace_in_array(array, range)
      array[range] = arg_string + "\n"
    end

    # @return [Fixnum] The number of lines currently in `eval_string` (the input buffer).
    def line_count
      eval_string.lines.count
    end

    # Returns the (one-indexed) start and end lines given by the user.
    # The lines in this range will be affected by the `amend-line`.
    # Returns `nil` if no lines were specified by the user.
    # @return [Array<Fixnum>, nil]
    def start_and_end_line_number
      start_line_number, end_line_number = args
      end_line_number ||= start_line_number.to_i

      [start_line_number.to_i, end_line_number.to_i] if start_line_number
    end

    # Takes two numbers that are 1-indexed, and returns a range (or
    # number) that is 0-indexed. 1-indexed means the first element is
    # indentified by 1 rather than by 0 (as is the case for Ruby arrays).
    # @param [Fixnum] start_line_number One-indexed number.
    # @param [Fixnum] end_line_number One-indexed number.
    # @return [Range] The zero-indexed range.
    def zero_indexed_range_from_one_indexed_numbers(start_line_number, end_line_number)
      # FIXME: one_index_number is a horrible name for this method
      one_index_number(start_line_number)..one_index_number(end_line_number)
    end

    # The lines (or line) that will be modified by the `amend-line`.
    # @return [Range, Fixnum] The lines or line.
    def line_range
      start_line_number, end_line_number = start_and_end_line_number
      if start_line_number
        zero_indexed_range_from_one_indexed_numbers(start_line_number,
                                                    end_line_number)
      else
        line_count - 1
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::AmendLine)
end
