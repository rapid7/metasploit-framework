require "helper"

module Nokogiri
  module CSS
    class TestNthiness < Nokogiri::TestCase
      def setup
        super
        doc = <<EOF
<html>
<table>
  <tr><td>row1 </td></tr>
  <tr><td>row2 </td></tr>
  <tr><td>row3 </td></tr>
  <tr><td>row4 </td></tr>
  <tr><td>row5 </td></tr>
  <tr><td>row6 </td></tr>
  <tr><td>row7 </td></tr>
  <tr><td>row8 </td></tr>
  <tr><td>row9 </td></tr>
  <tr><td>row10 </td></tr>
  <tr><td>row11 </td></tr>
  <tr><td>row12 </td></tr>
  <tr><td>row13 </td></tr>
  <tr><td>row14 </td></tr>
</table>
<div>
  <b>bold1 </b>
  <i>italic1 </i>
  <b>bold2 </b>
  <i>italic2 </i>
  <p>para1 </p>
  <b>bold3 </b>
</div>
<div>
  <p>para2 </p>
  <p>para3 </p>
</div>
<div>
  <p>para4 </p>
</div>
<p class='empty'></p>
<p class='not-empty'><b></b></p>
</html>
EOF
        @parser = Nokogiri.HTML doc
      end


      def test_even
        assert_result_rows [2,4,6,8,10,12,14], @parser.search("table/tr:nth(even)")
      end

      def test_odd
        assert_result_rows [1,3,5,7,9,11,13], @parser.search("table/tr:nth(odd)")
      end

      def test_2n
        assert_equal @parser.search("table/tr:nth(even)").inner_text, @parser.search("table/tr:nth(2n)").inner_text
      end

      def test_2np1
        assert_equal @parser.search("table/tr:nth(odd)").inner_text, @parser.search("table/tr:nth(2n+1)").inner_text
      end

      def test_4np3
        assert_result_rows [3,7,11], @parser.search("table/tr:nth(4n+3)")
      end

      def test_3np4
        assert_result_rows [4,7,10,13], @parser.search("table/tr:nth(3n+4)")
      end

      def test_mnp3
        assert_result_rows [1,2,3], @parser.search("table/tr:nth(-n+3)")
      end

      def test_np3
        assert_result_rows [3,4,5,6,7,8,9,10,11,12,13,14], @parser.search("table/tr:nth(n+3)")
      end

      def test_first
        assert_result_rows [1], @parser.search("table/tr:first")
        assert_result_rows [1], @parser.search("table/tr:first()")
      end

      def test_last
        assert_result_rows [14], @parser.search("table/tr:last")
        assert_result_rows [14], @parser.search("table/tr:last()")
      end

      def test_first_child
        assert_result_rows [1], @parser.search("div/b:first-child"), "bold"
        assert_result_rows [1], @parser.search("table/tr:first-child")
      end

      def test_last_child
        assert_result_rows [3], @parser.search("div/b:last-child"), "bold"
        assert_result_rows [14], @parser.search("table/tr:last-child")
      end

      def test_first_of_type
        assert_result_rows [1], @parser.search("table/tr:first-of-type")
        assert_result_rows [1], @parser.search("div/b:first-of-type"), "bold"
      end

      def test_last_of_type
        assert_result_rows [14], @parser.search("table/tr:last-of-type")
        assert_result_rows [3], @parser.search("div/b:last-of-type"), "bold"
      end

      def test_only_of_type
        assert_result_rows [1,4], @parser.search("div/p:only-of-type"), "para"
      end

      def test_only_child
        assert_result_rows [4], @parser.search("div/p:only-child"), "para"
      end

      def test_empty
        result = @parser.search("p:empty")
        assert_equal 1, result.size, "unexpected number of rows returned: '#{result.inner_text}'"
        assert_equal 'empty', result.first['class']
      end

      def test_parent
        result = @parser.search("p:parent")
        assert_equal 5, result.size
        0.upto(3) do |j|
          assert_equal "para#{j+1} ", result[j].inner_text
        end
        assert_equal "not-empty", result[4]['class']
      end

      def test_siblings
        doc = <<-EOF
<html><body><div>
<p id="1">p1 </p>
<p id="2">p2 </p>
<p id="3">p3 </p>
<p id="4">p4 </p>
<p id="5">p5 </p>
EOF
        parser = Nokogiri.HTML doc
        assert_equal 2, parser.search("#3 ~ p").size
        assert_equal "p4 p5 ", parser.search("#3 ~ p").inner_text
        assert_equal 0, parser.search("#5 ~ p").size

        assert_equal 1, parser.search("#3 + p").size
        assert_equal "p4 ", parser.search("#3 + p").inner_text
        assert_equal 0, parser.search("#5 + p").size
      end

      def assert_result_rows intarray, result, word="row"
        assert_equal intarray.size, result.size, "unexpected number of rows returned: '#{result.inner_text}'"
        assert_equal intarray.map{|j| "#{word}#{j}"}.join(' '), result.inner_text.strip, result.inner_text
      end
    end
  end
end
