# encoding: utf-8
require 'test/unit'
require File.expand_path('../../lib/assert_warning', __FILE__)

$:.unshift File.expand_path('../../../lib', __FILE__)
require 'coderay'

class BasicTest < Test::Unit::TestCase
  
  def test_version
    assert_nothing_raised do
      assert_match(/\A\d\.\d\.\d?\z/, CodeRay::VERSION)
    end
  end
  
  def with_empty_load_path
    old_load_path = $:.dup
    $:.clear
    yield
  ensure
    $:.replace old_load_path
  end
  
  def test_autoload
    with_empty_load_path do
      assert_nothing_raised do
        CodeRay::Scanners::Java::BuiltinTypes
      end
    end
  end
  
  RUBY_TEST_CODE = 'puts "Hello, World!"'
  
  RUBY_TEST_TOKENS = [
    ['puts', :ident],
    [' ', :space],
    [:begin_group, :string],
      ['"', :delimiter],
      ['Hello, World!', :content],
      ['"', :delimiter],
    [:end_group, :string]
  ].flatten
  def test_simple_scan
    assert_nothing_raised do
      assert_equal RUBY_TEST_TOKENS, CodeRay.scan(RUBY_TEST_CODE, :ruby).tokens
    end
  end
  
  RUBY_TEST_HTML = 'puts <span class="string"><span class="delimiter">&quot;</span>' + 
    '<span class="content">Hello, World!</span><span class="delimiter">&quot;</span></span>'
  def test_simple_highlight
    assert_nothing_raised do
      assert_equal RUBY_TEST_HTML, CodeRay.scan(RUBY_TEST_CODE, :ruby).html
    end
  end
  
  def test_scan_file
    CodeRay.scan_file __FILE__
  end
  
  def test_encode
    assert_equal 1, CodeRay.encode('test', :python, :count)
  end
  
  def test_encode_tokens
    assert_equal 1, CodeRay.encode_tokens(CodeRay::Tokens['test', :string], :count)
  end
  
  def test_encode_file
    assert_equal File.read(__FILE__), CodeRay.encode_file(__FILE__, :text)
  end
  
  def test_highlight
    assert_match '<pre>test</pre>', CodeRay.highlight('test', :python)
  end
  
  def test_highlight_file
    assert_match "require <span class=\"string\"><span class=\"delimiter\">'</span><span class=\"content\">test/unit</span><span class=\"delimiter\">'</span></span>\n", CodeRay.highlight_file(__FILE__)
  end
  
  def test_duo
    assert_equal(RUBY_TEST_CODE,
      CodeRay::Duo[:plain, :text].highlight(RUBY_TEST_CODE))
    assert_equal(RUBY_TEST_CODE,
      CodeRay::Duo[:plain => :text].highlight(RUBY_TEST_CODE))
  end
  
  def test_duo_stream
    assert_equal(RUBY_TEST_CODE,
      CodeRay::Duo[:plain, :text].highlight(RUBY_TEST_CODE, :stream => true))
  end
  
  def test_comment_filter
    assert_equal <<-EXPECTED, CodeRay.scan(<<-INPUT, :ruby).comment_filter.text
#!/usr/bin/env ruby

code

more code  
      EXPECTED
#!/usr/bin/env ruby
=begin
A multi-line comment.
=end
code
# A single-line comment.
more code  # and another comment, in-line.
      INPUT
  end
  
  def test_lines_of_code
    assert_equal 2, CodeRay.scan(<<-INPUT, :ruby).lines_of_code
#!/usr/bin/env ruby
=begin
A multi-line comment.
=end
code
# A single-line comment.
more code  # and another comment, in-line.
      INPUT
    rHTML = <<-RHTML
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <meta http-equiv="content-type" content="text/html;charset=UTF-8" />
  <title><%= controller.controller_name.titleize %>: <%= controller.action_name %></title>
  <%= stylesheet_link_tag 'scaffold' %>
</head>
<body>

<p style="color: green"><%= flash[:notice] %></p>

<div id="main">
  <%= yield %>
</div>

</body>
</html>
      RHTML
    assert_equal 0, CodeRay.scan(rHTML, :html).lines_of_code
    assert_equal 0, CodeRay.scan(rHTML, :php).lines_of_code
    assert_equal 0, CodeRay.scan(rHTML, :yaml).lines_of_code
    assert_equal 4, CodeRay.scan(rHTML, :erb).lines_of_code
  end
  
  def test_list_of_encoders
    assert_kind_of(Array, CodeRay::Encoders.list)
    assert CodeRay::Encoders.list.include?(:count)
  end
  
  def test_list_of_scanners
    assert_kind_of(Array, CodeRay::Scanners.list)
    assert CodeRay::Scanners.list.include?(:text)
  end
  
  def test_token_kinds
    assert_kind_of Hash, CodeRay::TokenKinds
    for kind, css_class in CodeRay::TokenKinds
      assert_kind_of Symbol, kind
      if css_class != false
        assert_kind_of String, css_class, "TokenKinds[%p] == %p" % [kind, css_class]
      end
    end
    assert_equal 'reserved', CodeRay::TokenKinds[:reserved]
    assert_warning 'Undefined Token kind: :shibboleet' do
      assert_equal false, CodeRay::TokenKinds[:shibboleet]
    end
  end
  
  class Milk < CodeRay::Encoders::Encoder
    FILE_EXTENSION = 'cocoa'
  end
  
  class HoneyBee < CodeRay::Encoders::Encoder
  end
  
  def test_encoder_file_extension
    assert_nothing_raised do
      assert_equal 'html', CodeRay::Encoders::Page::FILE_EXTENSION
      assert_equal 'cocoa', Milk::FILE_EXTENSION
      assert_equal 'cocoa', Milk.new.file_extension
      assert_equal 'honeybee', HoneyBee::FILE_EXTENSION
      assert_equal 'honeybee', HoneyBee.new.file_extension
    end
    assert_raise NameError do
      HoneyBee::MISSING_CONSTANT
    end
  end
  
  def test_encoder_tokens
    encoder = CodeRay::Encoders::Encoder.new
    encoder.send :setup, {}
    assert_raise(ArgumentError) { encoder.token :strange, '' }
    encoder.token 'test', :debug
  end
  
  def test_encoder_deprecated_interface
    encoder = CodeRay::Encoders::Encoder.new
    encoder.send :setup, {}
    assert_warning 'Using old Tokens#<< interface.' do
      encoder << ['test', :content]
    end
    assert_raise ArgumentError do
      encoder << [:strange, :input]
    end
    assert_raise ArgumentError do
      encoder.encode_tokens [['test', :token]]
    end
  end
  
  def encoder_token_interface_deprecation_warning_given
    CodeRay::Encoders::Encoder.send :class_variable_get, :@@CODERAY_TOKEN_INTERFACE_DEPRECATION_WARNING_GIVEN
  end
  
  def test_scanner_file_extension
    assert_equal 'rb', CodeRay::Scanners::Ruby.file_extension
    assert_equal 'rb', CodeRay::Scanners::Ruby.new.file_extension
    assert_equal 'java', CodeRay::Scanners::Java.file_extension
    assert_equal 'java', CodeRay::Scanners::Java.new.file_extension
  end
  
  def test_scanner_lang
    assert_equal :ruby, CodeRay::Scanners::Ruby.lang
    assert_equal :ruby, CodeRay::Scanners::Ruby.new.lang
    assert_equal :java, CodeRay::Scanners::Java.lang
    assert_equal :java, CodeRay::Scanners::Java.new.lang
  end
  
  def test_scanner_tokenize
    assert_equal ['foo', :plain], CodeRay::Scanners::Plain.new.tokenize('foo')
    assert_equal [['foo', :plain], ['bar', :plain]], CodeRay::Scanners::Plain.new.tokenize(['foo', 'bar'])
    CodeRay::Scanners::Plain.new.tokenize 42
  end
  
  def test_scanner_tokens
    scanner = CodeRay::Scanners::Plain.new
    scanner.tokenize('foo')
    assert_equal ['foo', :plain], scanner.tokens
    scanner.string = ''
    assert_equal ['', :plain], scanner.tokens
  end
  
  def test_scanner_line_and_column
    scanner = CodeRay::Scanners::Plain.new "foo\nbär+quux"
    assert_equal 0, scanner.pos
    assert_equal 1, scanner.line
    assert_equal 1, scanner.column
    scanner.scan(/foo/)
    assert_equal 3, scanner.pos
    assert_equal 1, scanner.line
    assert_equal 4, scanner.column
    scanner.scan(/\n/)
    assert_equal 4, scanner.pos
    assert_equal 2, scanner.line
    assert_equal 1, scanner.column
    scanner.scan(/b/)
    assert_equal 5, scanner.pos
    assert_equal 2, scanner.line
    assert_equal 2, scanner.column
    scanner.scan(/a/)
    assert_equal 5, scanner.pos
    assert_equal 2, scanner.line
    assert_equal 2, scanner.column
    scanner.scan(/ä/)
    assert_equal 7, scanner.pos
    assert_equal 2, scanner.line
    assert_equal 4, scanner.column
    scanner.scan(/r/)
    assert_equal 8, scanner.pos
    assert_equal 2, scanner.line
    assert_equal 5, scanner.column
  end
  
  def test_scanner_use_subclasses
    assert_raise NotImplementedError do
      CodeRay::Scanners::Scanner.new
    end
  end
  
  class InvalidScanner < CodeRay::Scanners::Scanner
  end
  
  def test_scanner_scan_tokens
    assert_raise NotImplementedError do
      InvalidScanner.new.tokenize ''
    end
  end
  
  class RaisingScanner < CodeRay::Scanners::Scanner
    def scan_tokens encoder, options
      raise_inspect 'message', [], :initial
    end
  end
  
  def test_scanner_raise_inspect
    assert_raise CodeRay::Scanners::Scanner::ScanError do
      RaisingScanner.new.tokenize ''
    end
  end
  
  def test_scan_a_frozen_string
    assert_nothing_raised do
      CodeRay.scan RUBY_VERSION, :ruby
      CodeRay.scan RUBY_VERSION, :plain
    end
  end
  
  def test_scan_a_non_string
    assert_nothing_raised do
      CodeRay.scan 42, :ruby
      CodeRay.scan nil, :ruby
      CodeRay.scan self, :ruby
      CodeRay.encode ENV.to_hash, :ruby, :page
      CodeRay.highlight CodeRay, :plain
    end
  end
  
end
