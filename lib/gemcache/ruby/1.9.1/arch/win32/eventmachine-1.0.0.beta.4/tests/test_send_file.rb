require 'em_test_helper'
require 'tempfile'

class TestSendFile < Test::Unit::TestCase

  if EM.respond_to?(:send_file_data)
    module TestModule
      def initialize filename
        @filename = filename
      end

      def post_init
        send_file_data @filename
        close_connection_after_writing
      end
    end

    module TestClient
      def data_to(&blk)
        @data_to = blk
      end

      def receive_data(data)
        @data_to.call(data) if @data_to
      end

      def unbind
        EM.stop
      end
    end

    def setup
      @file = Tempfile.new("em_test_file")
      @filename = @file.path
      @port = next_port
    end

    def test_send_file
      File.open( @filename, "w" ) {|f|
        f << ("A" * 5000)
      }

      data = ''

      EM.run {
        EM.start_server "127.0.0.1", @port, TestModule, @filename
        setup_timeout

        EM.connect "127.0.0.1", @port, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }

      assert_equal( "A" * 5000, data )
    end

    # EM::Connection#send_file_data has a strict upper limit on the filesize it will work with.
    def test_send_large_file
      File.open( @filename, "w" ) {|f|
        f << ("A" * 1000000)
      }

      data = ''

      assert_raises(RuntimeError) {
        EM.run {
          EM.start_server "127.0.0.1", @port, TestModule, @filename
          setup_timeout
          EM.connect "127.0.0.1", @port, TestClient do |c|
            c.data_to { |d| data << d }
          end
        }
      }
    end

    module StreamTestModule
      def initialize filename
        @filename = filename
      end

      def post_init
        EM::Deferrable.future( stream_file_data(@filename)) {
          close_connection_after_writing
        }
      end
    end

    module ChunkStreamTestModule
      def initialize filename
        @filename = filename
      end

      def post_init
        EM::Deferrable.future( stream_file_data(@filename, :http_chunks=>true)) {
          close_connection_after_writing
        }
      end
    end

    def test_stream_file_data
      File.open( @filename, "w" ) {|f|
        f << ("A" * 1000)
      }

      data = ''

      EM.run {
        EM.start_server "127.0.0.1", @port, StreamTestModule, @filename
        setup_timeout
        EM.connect "127.0.0.1", @port, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }

      assert_equal( "A" * 1000, data )
    end

    def test_stream_chunked_file_data
      File.open( @filename, "w" ) {|f|
        f << ("A" * 1000)
      }

      data = ''

      EM.run {
        EM.start_server "127.0.0.1", @port, ChunkStreamTestModule, @filename
        setup_timeout
        EM.connect "127.0.0.1", @port, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }

      assert_equal( "3e8\r\n#{"A" * 1000}\r\n0\r\n\r\n", data )
    end

    module BadFileTestModule
      def initialize filename
        @filename = filename
      end

      def post_init
        de = stream_file_data( @filename+".wrong" )
        de.errback {|msg|
          send_data msg
          close_connection_after_writing
        }
      end
    end
    def test_stream_bad_file
      data = ''
      EM.run {
        EM.start_server "127.0.0.1", @port, BadFileTestModule, @filename
        setup_timeout(5)
        EM.connect "127.0.0.1", @port, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }

      assert_equal( "file not found", data )
    end
  else
    warn "EM.send_file_data not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_send_file_data_not_implemented
      assert !EM.respond_to?(:send_file_data)
    end
  end

  begin
    require 'fastfilereaderext'

    def test_stream_large_file_data
      File.open( @filename, "w" ) {|f|
        f << ("A" * 10000)
      }

      data = ''

      EM.run {
        EM.start_server "127.0.0.1", @port, StreamTestModule, @filename
        setup_timeout
        EM.connect "127.0.0.1", @port, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }

      assert_equal( "A" * 10000, data )
    end

    def test_stream_large_chunked_file_data
      File.open( @filename, "w" ) {|f|
        f << ("A" * 100000)
      }

      data = ''

      EM.run {
        EM.start_server "127.0.0.1", @port, ChunkStreamTestModule, @filename
        setup_timeout
        EM.connect "127.0.0.1", @port, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }

      expected = [
        "4000\r\n#{"A" * 16384}\r\n" * 6,
        "6a0\r\n#{"A" * 0x6a0}\r\n",
        "0\r\n\r\n"
      ].join
      assert_equal( expected, data )
    end
  rescue LoadError
    warn "require 'fastfilereaderext' failed, skipping tests in #{__FILE__}"
  end

end
