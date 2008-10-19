#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/ui/text/color'

class Rex::Ui::Text::Color::UnitTest < Test::Unit::TestCase

	def test_color
		color  = Rex::Ui::Text::Color.ansi('bold', 'red')
		color += 'hey sup'
		color += Rex::Ui::Text::Color.ansi('clear')

		assert_equal("\e[1;31mhey sup\e[0m", color)
	end

end