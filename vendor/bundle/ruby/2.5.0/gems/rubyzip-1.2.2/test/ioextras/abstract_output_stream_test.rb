require 'test_helper'
require 'zip/ioextras'

class AbstractOutputStreamTest < MiniTest::Test
  class TestOutputStream
    include ::Zip::IOExtras::AbstractOutputStream

    attr_accessor :buffer

    def initialize
      @buffer = ''
    end

    def <<(data)
      @buffer << data
      self
    end
  end

  def setup
    @output_stream = TestOutputStream.new

    @origCommaSep = $,
    @origOutputSep = $\
  end

  def teardown
    $, = @origCommaSep
    $\ = @origOutputSep
  end

  def test_write
    count = @output_stream.write('a little string')
    assert_equal('a little string', @output_stream.buffer)
    assert_equal('a little string'.length, count)

    count = @output_stream.write('. a little more')
    assert_equal('a little string. a little more', @output_stream.buffer)
    assert_equal('. a little more'.length, count)
  end

  def test_print
    $\ = nil # record separator set to nil
    @output_stream.print('hello')
    assert_equal('hello', @output_stream.buffer)

    @output_stream.print(' world.')
    assert_equal('hello world.', @output_stream.buffer)

    @output_stream.print(' You ok ', 'out ', 'there?')
    assert_equal('hello world. You ok out there?', @output_stream.buffer)

    $\ = "\n"
    @output_stream.print
    assert_equal("hello world. You ok out there?\n", @output_stream.buffer)

    @output_stream.print('I sure hope so!')
    assert_equal("hello world. You ok out there?\nI sure hope so!\n", @output_stream.buffer)

    $, = 'X'
    @output_stream.buffer = ''
    @output_stream.print('monkey', 'duck', 'zebra')
    assert_equal("monkeyXduckXzebra\n", @output_stream.buffer)

    $\ = nil
    @output_stream.buffer = ''
    @output_stream.print(20)
    assert_equal('20', @output_stream.buffer)
  end

  def test_printf
    @output_stream.printf('%d %04x', 123, 123)
    assert_equal('123 007b', @output_stream.buffer)
  end

  def test_putc
    @output_stream.putc('A')
    assert_equal('A', @output_stream.buffer)
    @output_stream.putc(65)
    assert_equal('AA', @output_stream.buffer)
  end

  def test_puts
    @output_stream.puts
    assert_equal("\n", @output_stream.buffer)

    @output_stream.puts('hello', 'world')
    assert_equal("\nhello\nworld\n", @output_stream.buffer)

    @output_stream.buffer = ''
    @output_stream.puts("hello\n", "world\n")
    assert_equal("hello\nworld\n", @output_stream.buffer)

    @output_stream.buffer = ''
    @output_stream.puts(%W[hello\n world\n])
    assert_equal("hello\nworld\n", @output_stream.buffer)

    @output_stream.buffer = ''
    @output_stream.puts(%W[hello\n world\n], 'bingo')
    assert_equal("hello\nworld\nbingo\n", @output_stream.buffer)

    @output_stream.buffer = ''
    @output_stream.puts(16, 20, 50, 'hello')
    assert_equal("16\n20\n50\nhello\n", @output_stream.buffer)
  end
end
