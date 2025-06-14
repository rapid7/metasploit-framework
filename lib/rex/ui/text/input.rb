# -*- coding: binary -*-

module Rex
module Ui
module Text

###
#
# This class acts as a base for all input mediums.  It defines
# the interface that will be used by anything that wants to
# interact with a derived class.
#
###
class Input

  require 'rex/text/color'

  include Rex::Text::Color

  def initialize
    self.eof = false
    @config = {
      :readline => true, # true, false
      :color => :auto, # true, false, :auto
    }
    super
  end

  #
  # Whether or not the input medium supports readline.
  #
  def supports_readline
    return true if not @config

    config[:readline] == true
  end

  #
  # Stub for tab completion reset
  #
  def reset_tab_completion
  end

  #
  # Calls the underlying system read.
  #
  def sysread(len)
    raise NotImplementedError
  end

  #
  # Gets a line of input
  #
  def gets
    raise NotImplementedError
  end

  #
  # Has the input medium reached end-of-file?
  #
  def eof?
    return eof
  end

  #
  # Returns a pollable file descriptor that is associated with this
  # input medium.
  #
  def fd
    raise NotImplementedError
  end

  #
  # Indicates whether or not this input medium is intrinsicly a
  # shell provider.  This would indicate whether or not it
  # already expects to have a prompt.
  #
  def intrinsic_shell?
    false
  end

  def update_prompt(new_prompt = '', new_prompt_char = '')
    self.prompt = new_prompt + new_prompt_char
  end

  attr_reader :config

  def disable_readline
    return if not @config
    @config[:readline] = false
  end

  def enable_readline
    return if not @config
    @config[:readline] = true
  end

  def disable_color
    return if not @config
    @config[:color] = false
  end

  def enable_color
    return if not @config
    @config[:color] = true
  end

  def auto_color
    return if not @config
    @config[:color] = :auto
  end

  def update_prompt(prompt)
    substitute_colors(prompt, true)
  end

  def reset_color
  end

  attr_accessor :eof, :prompt, :prompt_char, :config

end

end
end
end
