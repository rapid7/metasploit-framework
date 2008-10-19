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
	def self.ansi(*attrs)
		attr = attrs.collect {|a| AnsiAttributes[a] ? AnsiAttributes[a] : nil}.compact.join(';')
		attr = "\e[%sm" % attr if (attr.empty? == false)
		return attr
	end

end 

end end end