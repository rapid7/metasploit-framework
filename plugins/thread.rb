module Msf
  class Plugin::ThreadTest < Msf::Plugin
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'ThreadTest'
      end

      def commands
        {
          'start_thread' => 'Start a background thread that writes to the console',
          'stop_thread' => 'Stop a background thread',
          'list_thread' => 'List running threads'
        }
      end

      def cmd_start_thread(*_args)
        if @mythread
          print_line('Test thread is already running')
          return
        end

        @mythread = ::Thread.new do
          loop do
            print_line('--- test thread ---')
            select(nil, nil, nil, 5)
          end
        end
        print_line('Test thread created')
      end

      def cmd_stop_thread(*_args)
        if !@mythread
          print_line('No test thread is running')
          return
        end

        @mythread.kill
        @mythread = nil
        print_line('Test thread stopped')
      end

      def cmd_list_thread(*_args)
        Thread.list.each do |t|
          print_line(format('Thread: 0x%.8x (%s/%d) (%s)', t.object_id, t.status, t.priority, t.tsource))
          print_line('')
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
    ", __FILE__, __LINE__ - 9)

      print_status('ThreadTest plugin loaded.')
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
      'threadtest'
    end

    #
    # This method returns a brief description of the plugin.  It should be no
    # more than 60 characters, but there are no hard limits.
    #
    def desc
      'Internal test tool for testing thread usage in Metasploit'
    end

  end
end
