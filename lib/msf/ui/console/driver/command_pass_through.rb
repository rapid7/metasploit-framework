# {#command_pass_through} allows {#unknown_command unknown commands} to be created as system commands in the console.
module Msf::Ui::Console::Driver::CommandPassThrough
  #
  # Attributes
  #

  # @!attribute [rw] command_pass_through
  #   Whether {#unknown_command unknown commands} should be treated as system commands.
  #
  #   @return [Boolean]
  attr_accessor :command_pass_through

  #
  # Methods
  #

  def command_pass_through?
    !!command_pass_through
  end

  # If an unknown command was passed, try to see if it's a valid local
  # executable.  This is only allowed if command passthru has been permitted
  #
  def unknown_command(method, line)
    if command_pass_through?
      [method, method+".exe"].each do |cmd|
        if Rex::FileUtils.find_full_path(cmd)

          print_status("exec: #{line}")
          print_line('')

          self.busy = true
          begin
            io = ::IO.popen(line, "r")
            io.each_line do |data|
              print(data)
            end
            io.close
          rescue ::Errno::EACCES, ::Errno::ENOENT
            print_error("Permission denied exec: #{line}")
          end
          self.busy = false
          return
        end
      end
    end

    super
  end
end
