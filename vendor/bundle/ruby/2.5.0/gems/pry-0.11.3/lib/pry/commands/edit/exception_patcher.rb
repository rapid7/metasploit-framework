class Pry
  class Command::Edit
    class ExceptionPatcher
      attr_accessor :_pry_
      attr_accessor :state
      attr_accessor :file_and_line

      def initialize(_pry_, state, exception_file_and_line)
        @_pry_ = _pry_
        @state = state
        @file_and_line = exception_file_and_line
      end

      # perform the patch
      def perform_patch
        file_name, _ = file_and_line
        lines = state.dynamical_ex_file || File.read(file_name)

        source = Pry::Editor.new(_pry_).edit_tempfile_with_content(lines)
        _pry_.evaluate_ruby source
        state.dynamical_ex_file = source.split("\n")
      end
    end
  end
end
