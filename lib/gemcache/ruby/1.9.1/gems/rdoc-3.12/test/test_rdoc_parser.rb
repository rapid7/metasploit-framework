require 'rdoc/test_case'

class TestRDocParser < RDoc::TestCase

  def setup
    super

    @RP = RDoc::Parser
    @binary_dat = File.expand_path '../binary.dat', __FILE__

    @fn = 'file.rb'
    @top_level = RDoc::TopLevel.new @fn
    @options = RDoc::Options.new
  end

  def test_class_binary_eh_marshal
    marshal = File.join Dir.tmpdir, "test_rdoc_parser_#{$$}.marshal"
    open marshal, 'wb' do |io|
      io.write Marshal.dump('')
      io.write 'lots of text ' * 500
    end

    assert @RP.binary?(marshal)
  ensure
    File.unlink marshal
  end

  def test_class_binary_japanese_text
    file_name = File.expand_path '../test.ja.txt', __FILE__
    refute @RP.binary?(file_name)
  end

  def test_class_binary_large_japanese_rdoc
    file_name = File.expand_path '../test.ja.large.rdoc', __FILE__
    assert !@RP.binary?(file_name)
  end

  def test_class_binary_japanese_rdoc
    skip "Encoding not implemented" unless Object.const_defined? :Encoding

    file_name = File.expand_path '../test.ja.rdoc', __FILE__
    refute @RP.binary?(file_name)
  end

  def test_class_can_parse
    assert_equal @RP.can_parse(__FILE__), @RP::Ruby

    readme_file_name = File.expand_path '../test.txt', __FILE__

    assert_equal @RP::Simple, @RP.can_parse(readme_file_name)

    assert_nil @RP.can_parse(@binary_dat)

    jtest_file_name = File.expand_path '../test.ja.txt', __FILE__
    assert_equal @RP::Simple, @RP.can_parse(jtest_file_name)

    jtest_rdoc_file_name = File.expand_path '../test.ja.rdoc', __FILE__
    assert_equal @RP::Simple, @RP.can_parse(jtest_rdoc_file_name)

    readme_file_name = File.expand_path '../README', __FILE__
    assert_equal @RP::Simple, @RP.can_parse(readme_file_name)
  end

  ##
  # Selenium hides a .jar file using a .txt extension.

  def test_class_can_parse_zip
    hidden_zip = File.expand_path '../hidden.zip.txt', __FILE__
    assert_nil @RP.can_parse(hidden_zip)
  end

  def test_class_for_binary
    rp = @RP.dup

    class << rp
      alias old_can_parse can_parse
    end

    def rp.can_parse(*args) nil end

    assert_nil @RP.for(nil, @binary_dat, nil, nil, nil)
  end

  def test_class_for_markup
    content = <<-CONTENT
# coding: utf-8 markup: rd
    CONTENT

    parser = @RP.for @top_level, __FILE__, content, @options, nil

    assert_kind_of @RP::RD, parser
  end

  def test_class_use_markup
    content = <<-CONTENT
# coding: utf-8 markup: rd
    CONTENT

    parser = @RP.use_markup content

    assert_equal @RP::RD, parser
  end

  def test_class_use_markup_modeline
    content = <<-CONTENT
# -*- coding: utf-8 -*-
# markup: rd
    CONTENT

    parser = @RP.use_markup content

    assert_equal @RP::RD, parser
  end

  def test_class_use_markup_modeline_shebang
    content = <<-CONTENT
#!/bin/sh
/* -*- coding: utf-8 -*-
 * markup: rd
 */
    CONTENT

    parser = @RP.use_markup content

    assert_equal @RP::RD, parser
  end

  def test_class_use_markup_shebang
    content = <<-CONTENT
#!/usr/bin/env ruby
# coding: utf-8 markup: rd
    CONTENT

    parser = @RP.use_markup content

    assert_equal @RP::RD, parser
  end

  def test_class_use_markup_tomdoc
    content = <<-CONTENT
# coding: utf-8 markup: tomdoc
    CONTENT

    parser = @RP.use_markup content

    assert_equal @RP::Ruby, parser
  end

  def test_class_use_markup_none
    parser = @RP.use_markup ''

    assert_nil parser
  end

  def test_initialize
    @RP.new @top_level, @fn, '', @options, nil

    assert_equal @RP, @top_level.parser
  end

end

