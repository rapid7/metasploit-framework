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

  # Tab completions for {#partial_word} when {#partial_word} is blank.
  #
  # @return [Array<String> `[]`
  def blank_tab_completions
    []
  end

  # Tab completions for when {#partial_word} when {#partial_word} is not blank.
  #
  # @return [Array<String>] `[]`
  def partial_tab_completions
    []
  end

  # Tab completions for {#partial_word}.  Calls {#blank_tab_completions} and {#partial_tab_completions} based on whether
  # {#partial_word} is blank or not.
  #
  # @return [Array<String>]
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