# -*- coding: utf-8 -*-
require "helper"

module Nokogiri
  module HTML
    if RUBY_VERSION =~ /^1\.9/
      class TestNodeEncoding < Nokogiri::TestCase
        def test_inner_html
          doc = Nokogiri::HTML File.open(SHIFT_JIS_HTML, 'rb')

          hello = "こんにちは"

          contents = doc.at('h2').inner_html
          assert_equal doc.encoding, contents.encoding.name
          assert_match hello.encode('Shift_JIS'), contents

          contents = doc.at('h2').inner_html(:encoding => 'UTF-8')
          assert_match hello, contents

          doc.encoding = 'UTF-8'
          contents = doc.at('h2').inner_html
          assert_match hello, contents
        end
      end
    end
  end
end
