#
# $Id$
# $Revision$
#

module Msf

###
#
# This class illustrates a sample plugin.  Plugins can change the behavior of
# the framework by adding new features, new user interface commands, or
# through any other arbitrary means.  They are designed to have a very loose
# definition in order to make them as useful as possible.
#
###
class Plugin::ThreadTest < Msf::Plugin

  ###
  #
  # This class implements a sample console command dispatcher.
  #
  ###
  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    #
    # The dispatcher's name.
    #
    def name
      "ThreadTest"
    end

    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands
      {
        "start_thread" => "Start a background thread that writes to the console",
        "stop_thread" => "Stop a background thread",
        "list_thread" => "List running threads"
      }
    end

    def cmd_start_thread(*args)
      if (@mythread)
        print_line("Test thread is already running")
        return
      end

      @mythread = ::Thread.new {
        while(true)
          print_line("--- test thread ---")
          Rex.sleep(5)
        end
      }
      print_line("Test thread created")
    end

    def cmd_stop_thread(*args)
      if (! @mythread)
        print_line("No test thread is running")
        return
      end

      @mythread.kill
      @mythread = nil
      print_line("Test thread stopped")
    end

    def cmd_list_thread(*args)
      Thread.list.each do |t|
        print_line(sprintf("Thread: 0x%.8x (%s/%d) (%s)", t.object_id, t.status, t.priority, t.tsource))
        print_line("")
      end
    end
  end

  #
  # The constructor is called when an instance of the plugin is created.  The
  # framework instance that the plugin is being associated with is passed in
  # the framework parameter.  Plugins should call the parent constructor when
  # inheriting from Msf::Plugin to ensure that the framework attribute on
  # their instance gets set.
  #
  def initialize(framework, opts)
    super

    # If this plugin is being loaded in the context of a console application
    # that uses the framework's console user interface driver, register
    # console dispatcher commands.
    add_console_dispatcher(ConsoleCommandDispatcher)

    # Extend the thread to track the calling source
    Thread.class_eval("
      attr_accessor :tsource

      alias initialize_old initialize

      def initialize(&block)
        self.tsource = caller(1)
        initialize_old(&block)
      end
    ")

    print_status("ThreadTest plugin loaded.")
  end

  #
  # The cleanup routine for plugins gives them a chance to undo any actions
  # they may have done to the framework.  For instance, if a console
  # dispatcher was added, then it should be removed in the cleanup routine.
  #
  def cleanup
    # If we had previously registered a console dispatcher with the console,
    # deregister it now.
    remove_console_dispatcher('ThreadTest')
  end

  #
  # This method returns a short, friendly name for the plugin.
  #
  def name
    "threadtest"
  end

  #
  # This method returns a brief description of the plugin.  It should be no
  # more than 60 characters, but there are no hard limits.
  #
  def desc
    "Thread testing plugin"
  end

protected
end

end
