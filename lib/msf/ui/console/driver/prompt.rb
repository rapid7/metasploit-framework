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

  # @note Only use if {Msf::Ui::Console::Driver#metasploit_instance} is `nil`, otherwise use
  #   {#restore_metasploit_instance_prompt}.
  #
  # {Updates the prompt #update_prompt} to its original value for {#framework}.
  #
  # @return [void]
  def restore_framework_prompt
    update_prompt(framework_prompt, framework_prompt_char, true)
  end

  # @note Only use if {Msf::Ui::Console::Driver#metasploit_instance} is not `nil`, otherwise use
  #   {#restore_framework_prompt}.
  #
  # @return [void]
  def restore_metasploit_instance_prompt
    update_prompt(
        "#{framework_prompt} #{metasploit_instance.module_type}(%bld%red#{metasploit_instance.short_name}%clr)",
        prompt_char,
        true
    )
  end

  # Restores the driver prompt, taking into account whether {Msf::Ui::Console::Driver#metasploit_instance} is set or
  # not.
  #
  # @return [void]
  def restore_prompt
    if metasploit_instance
      restore_metasploit_instance_prompt
    else
      restore_framework_prompt
    end
  end
end
