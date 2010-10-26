##
## Tests for the regexr library
## $Id$

$:.unshift(File.expand_path(File.dirname(__FILE__)) )

require 'test/unit'
require 'regexr'

class RegexrTest < Test::Unit::TestCase

	def setup
	 	@r = Regexr.new
	end

	def teardown 
	 	@r = nil
	end

	def test_determine_start
	 	assert @r.verify_start("this is the start\nof a line", "this is the start")
	end

	def test_determine_end
		assert @r.verify_end("this is the start\nof a line", "of a line")
	end

	def test_determine start_end
		assert @r.verify_start_and_end("this is the start\nof a line", "this is the start", "of a line")
	end

	def test_success_not_defined
		assert @r.ensure_all_exist_in_data("i can't get no\nsatisfaction")
	end

	def test_no_success
		assert !@r.ensure_all_exist_in_data("i can't get no\nsatisfaction", ["beast of burden"])
	end

	def test_single_success
		assert @r.ensure_all_exist_in_data("this is the start\nof a line\nbut it's not the end", ["of a line"])
	end

	def test_multiple_successes
		assert @r.ensure_all_exist_in_data("this is the start\nof a line\nbut it's not the end", ["this is the start","of a line"]) 
	end

	def test_failure_not_defined
		assert @r.ensure_none_exist_in_data("this is the start\nof a line\nbut it's not the end")
	end

	def test_no_failure
		assert @r.ensure_none_exist_in_data("this is the start\nof a line\nbut it's not the end", ["nope, no failure here"])
	end

	def test_single_failure
		assert !@r.ensure_none_exist_in_data("this is the start\nof a line\nbut it's not the end", ["of a line", "there's a failure here somewhere"])
	end

	def test_multiple_failures
		assert !@r.ensure_none_exist_in_data("this is the start\nof a line\nbut it's not the end", ["of a line","but it's not the end"])
	end

	def test_excepted_failure
		assert @r.ensure_none_exist_in_data("this is the start\nof a line\nbut it's not the end", ["no way man", "end"], ["but it's not the end"])
	end

	def test_success_and_failure
		assert @r.ensure_all_exist_in_data("this is the start\nof a line\nbut it's not the end", ["but it's not the end"])
		assert !@r.ensure_none_exist_in_data("this is the start\nof a line\nbut it's not the end", ["no way man", "end"])
	end

end
