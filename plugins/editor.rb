#
# $Id$
# $Revision$
#

module Msf

###
#
# This plugin is a simple editor command, designed to make it easy to edit modules in the console.
#
###
class Plugin::Editor < Msf::Plugin

  ###
  #
  # This class implements a single edit command.
  #
  ###
  class EditorCommandDispatcher
    include Msf::Ui::Console::ModuleCommandDispatcher

    #
    # The dispatcher's name.
    #
    def name
      "Editor"
    end

    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands
      # Don't update super here since we don't want the commands from
      # super, just the methods
      {
        "edit" => "A handy editor commmand"
      }
    end

    #
    # This method handles the edit command.
    #
    def cmd_edit(*args)
      print_line("Launching editor...")

      e = Rex::Compat.getenv("EDITOR") || "vi"

      if (not mod) or (not (path = mod.file_path))
        print_line("Error: No active module selected")
        return nil
      end

      ret = system(e, path)
      if not ret
        print_line("Failed to execute your editor (#{e})")
        return
      end

      reload
      ret
    end
  end

  def initialize(framework, opts)
    super

    # console dispatcher commands.
    add_console_dispatcher(EditorCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('Editor')
  end

  def name
    "editor"
  end

  def desc
    "Simple Editor Plugin"
  end

protected
end

end
