require 'em_test_helper'

# TODO!!! Need tests for overlength headers and text bodies.

class TestLineText2 < Test::Unit::TestCase

  # Run each of these tests two ways: passing in the whole test-dataset in one chunk,
  # and passing it in one character at a time.

  class Basic
    include EM::Protocols::LineText2
    attr_reader :lines
    def receive_line line
      (@lines ||= []) << line
    end
  end
  def test_basic
    testdata = "Line 1\nLine 2\r\nLine 3\n"

    a = Basic.new
    a.receive_data testdata
    assert_equal( ["Line 1", "Line 2", "Line 3"], a.lines )

    a = Basic.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    assert_equal( ["Line 1", "Line 2", "Line 3"], a.lines )
  end

  class ChangeDelimiter
    include EM::Protocols::LineText2
    attr_reader :lines
    def initialize *args
      super
      @delim = "A"
      set_delimiter @delim
    end
    def receive_line line
      (@lines ||= []) << line
      set_delimiter( @delim.succ! )
    end
  end

  def test_change_delimiter
    testdata = %Q(LineaALinebBLinecCLinedD)

    a = ChangeDelimiter.new
    a.receive_data testdata
    assert_equal( ["Linea", "Lineb", "Linec", "Lined"], a.lines )

    a = ChangeDelimiter.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    assert_equal( ["Linea", "Lineb", "Linec", "Lined"], a.lines )
  end


  #--
  # Test two lines followed by an empty line, ten bytes of binary data, then
  # two more lines.

  class Binary
    include EM::Protocols::LineText2
    attr_reader :lines, :body
    def initialize *args
      super
      @lines = []
      @body = nil
    end
    def receive_line ln
      if ln == ""
        set_text_mode 10
      else
        @lines << ln
      end
    end
    def receive_binary_data data
      @body = data
    end
  end

  def test_binary
    testdata = %Q(Line 1
Line 2

0000000000Line 3
Line 4
)

    a = Binary.new
    a.receive_data testdata
    assert_equal( ["Line 1", "Line 2", "Line 3", "Line 4"], a.lines)
    assert_equal( "0000000000", a.body )

    a = Binary.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    assert_equal( ["Line 1", "Line 2", "Line 3", "Line 4"], a.lines)
    assert_equal( "0000000000", a.body )
  end


  # Test unsized binary data. The expectation is that each chunk of it
  # will be passed to us as it it received.
  class UnsizedBinary
    include EM::Protocols::LineText2
    attr_reader :n_calls, :body
    def initialize *args
      super
      set_text_mode
    end
    def receive_binary_data data
      @n_calls ||= 0
      @n_calls += 1
      (@body ||= "") << data
    end
  end

  def test_unsized_binary
    testdata = "X\0" * 1000

    a = UnsizedBinary.new
    a.receive_data testdata
    assert_equal( 1, a.n_calls )
    assert_equal( testdata, a.body )

    a = UnsizedBinary.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    assert_equal( 2000, a.n_calls )
    assert_equal( testdata, a.body )
  end


  # Test binary data with a "throw back" into line-mode.
  class ThrowBack
    include EM::Protocols::LineText2
    attr_reader :headers
    def initialize *args
      super
      @headers = []
      @n_bytes = 0
      set_text_mode
    end
    def receive_binary_data data
      wanted = 25 - @n_bytes
      will_take = if data.length > wanted
                    data.length - wanted
                  else
                    data.length
                  end
      @n_bytes += will_take

      if @n_bytes == 25
        set_line_mode( data[will_take..-1] )
      end
    end
    def receive_line ln
      @headers << ln
    end
  end
  def test_throw_back
    testdata = "Line\n" * 10

    a = ThrowBack.new
    a.receive_data testdata
    assert_equal( ["Line"] * 5, a.headers )

    a = ThrowBack.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    assert_equal( ["Line"] * 5, a.headers )
  end

  # Test multi-character line delimiters.
  # Also note that the test data has a "tail" with no delimiter, that will be
  # discarded, but cf. the BinaryTail test.
  # TODO!!! This test doesn't work in the byte-by-byte case.
  class Multichar
    include EM::Protocols::LineText2
    attr_reader :lines
    def initialize *args
      super
      @lines = []
      set_delimiter "012"
    end
    def receive_line ln
      @lines << ln
    end
  end
  def test_multichar
    testdata = "Line012Line012Line012Line"

    a = Multichar.new
    a.receive_data testdata
    assert_equal( ["Line"]*3, a.lines )

    a = Multichar.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    # DOESN'T WORK in this case. Multi-character delimiters are broken.
    #assert_equal( ["Line"]*3, a.lines )
  end

  # Test a binary "tail," when a sized binary transfer doesn't complete because
  # of an unbind. We get a partial result.
  class BinaryTail
    include EM::Protocols::LineText2
    attr_reader :data
    def initialize *args
      super
      @data = ""
      set_text_mode 1000
    end
    def receive_binary_data data
      # we expect to get all the data in one chunk, even in the byte-by-byte case,
      # because sized transfers by definition give us exactly one call to
      # #receive_binary_data.
      @data = data
    end
  end
  def test_binary_tail
    testdata = "0" * 500

    a = BinaryTail.new
    a.receive_data testdata
    a.unbind
    assert_equal( "0" * 500, a.data )

    a = BinaryTail.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    a.unbind
    assert_equal( "0" * 500, a.data )
  end


  # Test an end-of-binary call. Arrange to receive binary data but don't bother counting it
  # as it comes. Rely on getting receive_end_of_binary_data to signal the transition back to
  # line mode.
  # At the present time, this isn't strictly necessary with sized binary chunks because by
  # definition we accumulate them and make exactly one call to receive_binary_data, but
  # we may want to support a mode in the future that would break up large chunks into multiple
  # calls.
  class LazyBinary
    include EM::Protocols::LineText2
    attr_reader :data, :end
    def initialize *args
      super
      @data = ""
      set_text_mode 1000
    end
    def receive_binary_data data
      # we expect to get all the data in one chunk, even in the byte-by-byte case,
      # because sized transfers by definition give us exactly one call to
      # #receive_binary_data.
      @data = data
    end
    def receive_end_of_binary_data
      @end = true
    end
  end
  def test_receive_end_of_binary_data
    testdata = "_" * 1000
    a = LazyBinary.new
    testdata.length.times {|i| a.receive_data( testdata[i...i+1] ) }
    assert_equal( "_" * 1000, a.data )
    assert( a.end )
  end


  # This tests a bug fix in which calling set_text_mode failed when called
  # inside receive_binary_data.
  #
  class BinaryPair
    include EM::Protocols::LineText2
    attr_reader :sizes
    def initialize *args
      super
      set_text_mode 1
      @sizes = []
    end
    def receive_binary_data dt
      @sizes <<  dt.length
      set_text_mode( (dt.length == 1) ? 2 : 1 )
    end
  end
  def test_binary_pairs
    test_data = "123" * 5
    a = BinaryPair.new
    a.receive_data test_data
    assert_equal( [1,2,1,2,1,2,1,2,1,2], a.sizes )
  end

end
