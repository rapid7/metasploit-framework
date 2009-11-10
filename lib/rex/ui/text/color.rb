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

	def substitute_colors(msg)
		str = msg.dup
		str.gsub!(/%cya/, colorize('cyan'))
		str.gsub!(/%red/, colorize('red'))
		str.gsub!(/%grn/, colorize('green'))
		str.gsub!(/%blu/, colorize('blue'))
		str.gsub!(/%yel/, colorize('yellow'))
		str.gsub!(/%whi/, colorize('white'))
		str.gsub!(/%mag/, colorize('magenta'))
		str.gsub!(/%blk/, colorize('black'))
		str.gsub!(/%dred/, colorize('dark', 'red'))
		str.gsub!(/%dgrn/, colorize('dark', 'green'))
		str.gsub!(/%dblu/, colorize('dark', 'blue'))
		str.gsub!(/%dyel/, colorize('dark', 'yellow'))
		str.gsub!(/%dcya/, colorize('dark', 'cyan'))
		str.gsub!(/%dwhi/, colorize('dark', 'white'))
		str.gsub!(/%dmag/, colorize('dark', 'magenta'))
		str.gsub!(/%u/, colorize('underline'))
		str.gsub!(/%b/, colorize('bold'))
		str.gsub!(/%c/, colorize('clear'))

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
