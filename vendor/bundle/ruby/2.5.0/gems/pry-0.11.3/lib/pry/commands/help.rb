class Pry
  class Command::Help < Pry::ClassCommand
    match 'help'
    group 'Help'
    description 'Show a list of commands or information about a specific command.'

    banner <<-'BANNER'
      Usage: help [COMMAND]

      With no arguments, help lists all the available commands along with their
      descriptions. When given a command name as an argument, shows the help
      for that command.
    BANNER

    # We only want to show commands that have descriptions, so that the
    # easter eggs don't show up.
    def visible_commands
      visible = {}
      commands.each do |key, command|
        visible[key] = command if command.description && !command.description.empty?
      end
      visible
    end

    # Get a hash of available commands grouped by the "group" name.
    def command_groups
      visible_commands.values.group_by(&:group)
    end

    def process
      if args.empty?
        display_index(command_groups)
      else
        display_search(args.first)
      end
    end

    # Display the index view, with headings and short descriptions per command.
    #
    # @param [Hash<String, Array<Commands>>] groups
    def display_index(groups)
      help_text = []

      sorted_group_names(groups).each do |group_name|
        commands = sorted_commands(groups[group_name])

        if commands.any?
           help_text << help_text_for_commands(group_name, commands)
        end
      end

      _pry_.pager.page help_text.join("\n\n")
    end

    # Given a group name and an array of commands,
    # return the help string for those commands.
    #
    # @param [String] name The group name.
    # @param [Array<Pry::Command>] commands
    # @return [String] The generated help string.
    def help_text_for_commands(name, commands)
      "#{text.bold(name.capitalize)}\n" << commands.map do |command|
        "  #{command.options[:listing].to_s.ljust(18)} #{command.description.capitalize}"
      end.join("\n")
    end

    # @param [Hash] groups
    # @return [Array<String>] An array of sorted group names.
    def sorted_group_names(groups)
      groups.keys.sort_by(&method(:group_sort_key))
    end

    # Sort an array of commands by their `listing` name.
    #
    # @param [Array<Pry::Command>] commands The commands to sort
    # @return [Array<Pry::Command>] commands sorted by listing name.
    def sorted_commands(commands)
      commands.sort_by{ |command| command.options[:listing].to_s }
    end

    # Display help for an individual command or group.
    #
    # @param [String] search  The string to search for.
    def display_search(search)
      if command = command_set.find_command_for_help(search)
        display_command(command)
      else
        display_filtered_search_results(search)
      end
    end

    # Display help for a searched item, filtered first by group
    # and if that fails, filtered by command name.
    #
    # @param [String] search The string to search for.
    def display_filtered_search_results(search)
      groups = search_hash(search, command_groups)

      if groups.size > 0
        display_index(groups)
      else
        display_filtered_commands(search)
      end
    end

    # Display help for a searched item, filtered by group
    #
    # @param [String] search The string to search for.
    def display_filtered_commands(search)
      filtered = search_hash(search, visible_commands)
      raise CommandError, "No help found for '#{args.first}'" if filtered.empty?

      if filtered.size == 1
        display_command(filtered.values.first)
      else
        display_index({"'#{search}' commands" => filtered.values})
      end
    end

    # Display help for an individual command.
    #
    # @param [Pry::Command] command
    def display_command(command)
      _pry_.pager.page command.new.help
    end

    # Find a subset of a hash that matches the user's search term.
    #
    # If there's an exact match a Hash of one element will be returned,
    # otherwise a sub-Hash with every key that matches the search will
    # be returned.
    #
    # @param [String] search the search term
    # @param [Hash] hash the hash to search
    def search_hash(search, hash)
      matching = {}

      hash.each_pair do |key, value|
        next unless key.is_a?(String)
        if normalize(key) == normalize(search)
          return {key => value}
        elsif normalize(key).start_with?(normalize(search))
          matching[key] = value
        end
      end

      matching
    end

    # Clean search terms to make it easier to search group names
    #
    # @param [String] key
    # @return [String]
    def normalize(key)
      key.downcase.gsub(/pry\W+/, '')
    end

    def group_sort_key(group_name)
      [%w(Help Context Editing Introspection Input_and_output Navigating_pry Gems Basic Commands).index(group_name.gsub(' ', '_')) || 99, group_name]
    end
  end

  Pry::Commands.add_command(Pry::Command::Help)
end
