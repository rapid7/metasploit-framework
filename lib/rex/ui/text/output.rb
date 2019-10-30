# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements text-based output but is not
# tied to an output medium.
#
###
class Output < Rex::Ui::Output

  require 'rex/ui/text/output/stdio'
  require 'rex/ui/text/output/socket'
  require 'rex/ui/text/output/buffer'
  require 'rex/ui/text/output/file'
  require 'rex/ui/text/output/tee'
  require 'rex/text/color'

  include Rex::Text::Color

  def initialize
    @config = {
      :color => :auto, # true, false, :auto
    }
    super
  end
  attr_reader :config
  attr_accessor :input

  def disable_color
    @config[:color] = false
  end

  def enable_color
    @config[:color] = true
  end

  def auto_color
    @config[:color] = :auto
  end

  def update_prompt(prompt = nil)
    return if prompt.nil?
    substitute_colors(prompt, true)
  end

  def print_error(msg = '')
    print_line("%bld%red[-]%clr #{msg}")
  end

  alias_method :print_bad, :print_error

  def print_good(msg = '')
    print_line("%bld%grn[+]%clr #{msg}")
  end

  def print_status(msg = '')
    print_line("%bld%blu[*]%clr #{msg}")
  end

  def print_line(msg = '')
   print(msg + "\n")
  end

  def print_warning(msg = '')
    print_line("%bld%yel[!]%clr #{msg}")
  end

  def print(msg = '')
    print_raw(substitute_colors(msg))
  end

  def reset
  end

  def puts(*args)
    args.each do |argument|
      line = argument.to_s
      print_raw(line)

      unless line.ends_with? "\n"
        # yes, this is output, but `IO#puts` uses `rb_default_rs`, which is
        # [`$/`](https://github.com/ruby/ruby/blob/3af8e150aded9d162bfd41426aaaae0279e5a653/io.c#L12168-L12172),
        # which is [`$INPUT_RECORD_SEPARATOR`](https://github.com/ruby/ruby/blob/3af8e150aded9d162bfd41426aaaae0279e5a653/lib/English.rb#L83)
        print_raw($INPUT_RECORD_SEPARATOR)
      end
    end

    nil
  end
end

end
end
end

