module Msf::Ui::Console::CommandDispatcher::Core::Threads
  CMD_THREADS_ONCE_OPTIONS = [
      '-K',
      '-h',
      '-v'
  ]
  CMD_THREADS_OPTIONS = Rex::Parser::Arguments.new(
    "-K" => [ false, "Terminate all non-critical threads."            ],
    "-h" => [ false, "Help banner."                                   ],
    "-i" => [ true,  "Lists detailed information about a thread."     ],
    "-k" => [ true,  "Terminate the specified thread name."           ],
    "-l" => [ false, "List all background threads."                   ],
    "-v" => [ false, "Print more detailed info.  Use with -i."  ]
  )

  #
  # Displays and manages running background threads
  #
  def cmd_threads(*args)
    # Make the default behavior listing all jobs if there were no options
    # or the only option is the verbose flag
    if args.empty?
      args.unshift("-l")
    end

    subcommand_options = {
        verbose: false
    }
    subcommands = []

    # Parse the command options
    CMD_THREADS_OPTIONS.parse(args) { |option, _index, value|
      case option
        when "-K"
          subcommands << :kill_all_non_critical
        when "-h"
          subcommands << [:help]
        when "-i"
          subcommands << [:info, value]
        when "-k"
          subcommands << [:kill, value]
        when "-l"
          subcommands << :list
        when "-v"
          subcommand_options[:verbose] = true
      end
    }

    subcommands.each do |subcommand|
      subcommand_with_arguments = Array.wrap(subcommand)

      suffix = subcommand_with_arguments.first
      method_name = "#{__method__}_#{suffix}".to_sym

      subcommand_arguments = subcommand_with_arguments[1 .. -1]
      send(method_name, *subcommand_arguments, subcommand_options)
    end
  end

  def cmd_threads_help(_options={})
    print_line "Usage: threads [options]"
    print_line
    print_line "Background thread management."
    print_line CMD_THREADS_OPTIONS.usage()
  end

  #
  # Tab completion for the threads command
  #
  # @param partial_word [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_threads_tabs(partial_word, words)
    last_word = words.last

    if ['-i', '-k'].include? last_word
      completions = framework.threads.list.collect { |thread|
        metasploit_framework_thread = thread[:metasploit_framework_thread]
        metasploit_framework_thread.name
      }
    else
      all_options = CMD_THREADS_OPTIONS.fmt.keys
      once_options = words & CMD_THREADS_ONCE_OPTIONS
      completions = all_options - once_options
    end

    completions
  end

  private

  def cmd_threads_info(name, options={})
    verbose = options[:verbose] || false

    cmd_threads_with_thread_named(name) do |thread|
      metasploit_framework_thread = thread[:metasploit_framework_thread]

      lines = []
      lines << ''
      lines << "Name:     #{metasploit_framework_thread.name}"

      # status is false when thread is dead
      formatted_status = thread.status || 'dead'
      lines << "Status:   #{formatted_status}"

      formatted_critical = metasploit_framework_thread.critical.to_s.capitalize
      lines << "Critical: #{formatted_critical}"

      lines << "Spawned:  #{metasploit_framework_thread.spawned_at}"

      if verbose
        lines << ''

        lines << 'Thread Source'
        lines << '============='

        metasploit_framework_thread.backtrace.each do |backtrace_line|
          lines << "  #{backtrace_line}"
        end
      end

      # so there is a trailing newline
      lines << ''

      formatted = lines.join("\n")
      print(formatted)
    end
  end

  def cmd_threads_kill(name, _options={})
    cmd_threads_with_thread_named(name) do |thread|
      cmd_threads_kill_thread(thread)
    end
  end

  def cmd_threads_kill_all_non_critical(_options={})
    print_line("Killing all non-critical threads...")

    framework.threads.list.each do |thread|
      metasploit_framework_thread = thread[:metasploit_framework_thread]

      unless metasploit_framework_thread.critical
        cmd_threads_kill_thread(thread)
      end
    end
  end

  def cmd_threads_kill_thread(thread)
    metasploit_framework_thread = thread[:metasploit_framework_thread]
    print_line("Terminating thread: #{metasploit_framework_thread.name}...")
    thread.kill
  end

  def cmd_threads_list(_options={})
    table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header'  => "Background Threads",
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' =>
            [
                'Name',
                'Status',
                'Critical',
                'Spawned'
            ]
    )

    framework.threads.list.each do |thread|
      metasploit_framework_thread = thread[:metasploit_framework_thread]

      formatted_name = metasploit_framework_thread.name
      formatted_status = thread.status || "dead"
      formatted_critical = metasploit_framework_thread.critical.to_s.capitalize
      formatted_spawned_at = metasploit_framework_thread.spawned_at.to_s

      row = [
          formatted_name,
          formatted_status,
          formatted_critical,
          formatted_spawned_at
      ]
      table << row
    end

    print(table.to_s)
  end

  def cmd_threads_thread_named(name)
    framework.threads.list.find { |thread|
      metasploit_framework_thread = thread[:metasploit_framework_thread]

      metasploit_framework_thread.name == name
    }
  end

  def cmd_threads_with_thread_named(name, &block)
    thread = cmd_threads_thread_named(name)

    if thread
      yield thread
    else
      print_error('Invalid Thread Name')
    end
  end

  def commands
    super.merge(
        'threads'  => 'View and manipulate background threads'
    )
  end
end