module Metasploit::Framework::Command::Use::SetMetasploitInstance::TabCompletion
  #
  # Methods
  #

  # All module class full names.
  #
  # @return [Array<String>] Array of `Mdm::Module::Class#full_name`s
  def blank_tab_completions
    completions = []

    # use only accepts a single argument: either (1) -h/--help OR (2) a module class full name, so tab completion
    # should only work on the first word
    if words.empty?
      completions += option_parser.candidate('-')
      completions += Mdm::Module::Class.pluck(:full_name)
    end

    completions
  end

  # All module class full names that start with {#partial_word}.
  #
  # @return [Array<String>] Array of `Mdm::Module::Class#full_name`s
  def partial_tab_completions
    completions = []

    # use only accepts a single argument: either (1) -h/--help OR (2) a module class full name, so tab completion
    # should only work on the first word
    if words.empty?
      completions = option_parser.candidate(partial_word)

      if completions.empty?
        completions = Mdm::Module::Class.where(
            Mdm::Module::Class.arel_table[:full_name].matches("#{escaped_partial_word}%")
        ).pluck(:full_name)
      end
    end

    completions
  end

  private

  # Escape special characters '%' (match multiple characters) and '_' (match single character) for `LIKE` queries.
  #
  # @return [String]
  def escaped_partial_word
    partial_word.gsub(/[%_]/) { |character|
      "\\#{character}"
    }
  end
end
