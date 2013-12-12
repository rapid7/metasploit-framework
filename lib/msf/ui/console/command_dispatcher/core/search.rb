# Defines helper methods for the `search` command.
module Msf::Ui::Console::CommandDispatcher::Core::Search
  # Searches modules.
  #
  # @return [void]
  def cmd_search(*args)
    command = Metasploit::Framework::Command::Search.new(dispatcher: self, words: args)
    command.run
  end

  # Prints help for `search` command.
  #
  # @return [void]
  def cmd_search_help
    cmd_search('--help')
  end

  # Tab completion for the search command.
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  #   at least 1 when tab completion has reached this stage since the command itself has been completed
  # @return [Array<String>] tab completions
  def cmd_search_tabs(partial_word, words)
    # first word is always command name
    command_words = words[1 .. -1]
    command = Metasploit::Framework::Command::Search.new(
        dispatcher: self,
        partial_word: partial_word,
        words: command_words
    )
    command.tab_completions
  end
end