require 'test_helper'
require 'zip/ioextras'

class AbstractInputStreamTest < MiniTest::Test
  # AbstractInputStream subclass that provides a read method

  TEST_LINES = ["Hello world#{$/}",
                "this is the second line#{$/}",
                'this is the last line']
  TEST_STRING = TEST_LINES.join
  class TestAbstractInputStream
    include ::Zip::IOExtras::AbstractInputStream

    def initialize(aString)
      super()
      @contents = aString
      @readPointer = 0
    end

    def sysread(charsToRead, _buf = nil)
      retVal = @contents[@readPointer, charsToRead]
      @readPointer += charsToRead
      retVal
    end

    def produce_input
      sysread(100)
    end

    def input_finished?
      @contents[@readPointer].nil?
    end
  end

  def setup
    @io = TestAbstractInputStream.new(TEST_STRING)
  end

  def test_gets
    assert_equal(TEST_LINES[0], @io.gets)
    assert_equal(1, @io.lineno)
    assert_equal(TEST_LINES[0].length, @io.pos)
    assert_equal(TEST_LINES[1], @io.gets)
    assert_equal(2, @io.lineno)
    assert_equal(TEST_LINES[2], @io.gets)
    assert_equal(3, @io.lineno)
    assert_nil(@io.gets)
    assert_equal(4, @io.lineno)
  end

  def test_gets_multi_char_seperator
    assert_equal('Hell', @io.gets('ll'))
    assert_equal("o world#{$/}this is the second l", @io.gets('d l'))
  end

  LONG_LINES = [
    'x' * 48 + "\r\n",
    'y' * 49 + "\r\n",
    'rest'
  ]

  def test_gets_mulit_char_seperator_split
    io = TestAbstractInputStream.new(LONG_LINES.join)
    assert_equal(LONG_LINES[0], io.gets("\r\n"))
    assert_equal(LONG_LINES[1], io.gets("\r\n"))
    assert_equal(LONG_LINES[2], io.gets("\r\n"))
  end

  def test_gets_with_sep_and_index
    io = TestAbstractInputStream.new(LONG_LINES.join)
    assert_equal('x', io.gets("\r\n", 1))
    assert_equal('x' * 47 + "\r", io.gets("\r\n", 48))
    assert_equal("\n", io.gets(nil, 1))
    assert_equal('yy', io.gets(nil, 2))
  end

  def test_gets_with_index
    assert_equal(TEST_LINES[0], @io.gets(100))
    assert_equal('this', @io.gets(4))
  end

  def test_each_line
    lineNumber = 0
    @io.each_line do |line|
      assert_equal(TEST_LINES[lineNumber], line)
      lineNumber += 1
    end
  end

  def test_readlines
    assert_equal(TEST_LINES, @io.readlines)
  end

  def test_readline
    test_gets
    begin
      @io.readline
      fail 'EOFError expected'
    rescue EOFError
    end
  end
end
