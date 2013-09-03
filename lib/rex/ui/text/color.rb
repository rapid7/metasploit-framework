# -*- coding: binary -*-
module Rex
module Ui
module Text

###
#
# This module provides an interface to getting ANSI color codes.
# It's taken mostly from perl's Term::ANSIColor by Russ Allbery
# <rra@stanford.edu> and Zenin <zenin@best.com>.
#
###
module Color

	AnsiAttributes =
		{
			'clear'      => 0,
			'reset'      => 0,
			'bold'       => 1,
			'dark'       => 2,
			'underline'  => 4,
			'underscore' => 4,
			'blink'      => 5,
			'reverse'    => 7,
			'concealed'  => 8,
			'black'      => 30,   'on_black'   => 40,
			'red'        => 31,   'on_red'     => 41,
			'green'      => 32,   'on_green'   => 42,
			'yellow'     => 33,   'on_yellow'  => 43,
			'blue'       => 34,   'on_blue'    => 44,
			'magenta'    => 35,   'on_magenta' => 45,
			'cyan'       => 36,   'on_cyan'    => 46,
			'white'      => 37,   'on_white'   => 47
		}

	#
	# Return a string with ANSI codes substituted.  Derived from code
	# written by The FaerieMUD Consortium.
	#
	def ansi(*attrs)
		attr = attrs.collect {|a| AnsiAttributes[a] ? AnsiAttributes[a] : nil}.compact.join(';')
		attr = "\e[%sm" % attr if (attr.empty? == false)
		return attr
	end

	#
	# Colorize if this shell supports it
	#
	def colorize(*color)
		supports_color?() ? ansi(*color) : ''
	end

	def substitute_colors(msg, in_prompt = nil)
		str = msg.dup
		pre_color = post_color = ''
		if (in_prompt)
			pre_color = "\x01"  # RL_PROMPT_START_IGNORE
			post_color = "\x02" # RL_PROMPT_END_IGNORE
		end
		str.gsub!(/%cya/, pre_color+colorize('cyan')+post_color)
		str.gsub!(/%red/, pre_color+colorize('red')+post_color)
		str.gsub!(/%grn/, pre_color+colorize('green')+post_color)
		str.gsub!(/%blu/, pre_color+colorize('blue')+post_color)
		str.gsub!(/%yel/, pre_color+colorize('yellow')+post_color)
		str.gsub!(/%whi/, pre_color+colorize('white')+post_color)
		str.gsub!(/%mag/, pre_color+colorize('magenta')+post_color)
		str.gsub!(/%blk/, pre_color+colorize('black')+post_color)
		str.gsub!(/%dred/, pre_color+colorize('dark', 'red')+post_color)
		str.gsub!(/%dgrn/, pre_color+colorize('dark', 'green')+post_color)
		str.gsub!(/%dblu/, pre_color+colorize('dark', 'blue')+post_color)
		str.gsub!(/%dyel/, pre_color+colorize('dark', 'yellow')+post_color)
		str.gsub!(/%dcya/, pre_color+colorize('dark', 'cyan')+post_color)
		str.gsub!(/%dwhi/, pre_color+colorize('dark', 'white')+post_color)
		str.gsub!(/%dmag/, pre_color+colorize('dark', 'magenta')+post_color)
		str.gsub!(/%und/, pre_color+colorize('underline')+post_color)
		str.gsub!(/%bld/, pre_color+colorize('bold')+post_color)
		str.gsub!(/%clr/, pre_color+colorize('clear')+post_color)

		str
	end

	#
	# Resets coloring so that it's back to normal.
	#
	def reset_color
		return if not supports_color?
		print(colorize('clear'))
	end

	#
	# Colorize if this shell supports it
	#
	def do_colorize(*color)
		supports_color?() ? ansi(*color) : ''
	end
end

end end end
