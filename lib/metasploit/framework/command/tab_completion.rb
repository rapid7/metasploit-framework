module Metasploit::Framework::Command::TabCompletion
  #
  # Attributes
  #

  # @!attribute [rw] partial_word
  #   Word being tab completed.
  #
  #   @return [String]
  attr_accessor :partial_word

  #
  # Methods
  #

  def tab_completions
    parse_words

    if partial_word.blank?
      completions = blank_tab_completions
    else
      completions = partial_tab_completions
    end

    completions
  end
end