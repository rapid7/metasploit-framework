# Concerning the prompt for {Msf::Ui::Console::Driver}.
module Msf::Ui::Console::Driver::Prompt
  #
  # CONSTANTS
  #

  DEFAULT_PROMPT     = "%undmsf%clr"
  DEFAULT_PROMPT_CHAR = "%clr>"

  #
  # Methods
  #

  def framework_prompt
    framework.datastore['Prompt'] || DEFAULT_PROMPT
  end

  def framework_prompt_char
    framework.datastore['PromptChar'] || DEFAULT_PROMPT_CHAR
  end

  # {Updates the prompt #update_prompt} to its original value for {#framework}
  def restore_prompt
    update_prompt(framework_prompt, framework_prompt_char, true)
  end
end
