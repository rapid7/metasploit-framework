#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/ui/text/table'

class Rex::Ui::Text::Table::UnitTest < Test::Unit::TestCase

	def new_table(opts = {})
		if (opts['Columns'] == nil)
			opts['Columns'] = 
				[
					'col1',
					'col2',
					'col3'
				]
		end

		tbl = Rex::Ui::Text::Table.new(opts)

		tbl << [ "r1cell1", "r1cell2", "r1cell3" ]
		tbl << [ "r2cell1", "r2cell2", "r2cell3" ]

		return tbl
	end

	def test_basic
		tbl = new_table

		dstr = <<End 
col1     col2     col3     
----     ----     ----     
r1cell1  r1cell2  r1cell3  
r2cell1  r2cell2  r2cell3  
End

		assert_equal(tbl.to_s, dstr)
	end

	def test_indent
		tbl = new_table(
			'Indent' => 4)

		dstr = <<End 
    col1     col2     col3     
    ----     ----     ----     
    r1cell1  r1cell2  r1cell3  
    r2cell1  r2cell2  r2cell3  
End

		assert_equal(tbl.to_s, dstr)
	end

end