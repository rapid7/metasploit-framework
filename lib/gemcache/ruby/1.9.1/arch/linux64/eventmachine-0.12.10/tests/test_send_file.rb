# $Id$
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 8 April 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
#
# 

$:.unshift "../lib"
require 'eventmachine'
require 'socket'
require 'test/unit'

class TestSendFile < Test::Unit::TestCase

  module TestModule
    def post_init
      send_file_data TestFilename
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

  TestHost = "0.0.0.0"
  TestPort = 9055
  TestFilename = "./xxxxxx"

  def setup
  end

  def teardown
    File.unlink( TestFilename ) if File.exist?( TestFilename )
  end

  def test_send_file
    File.open( TestFilename, "w" ) {|f|
      f << ("A" * 5000)
    }

    data = ''

    EM.run {
      EM.start_server TestHost, TestPort, TestModule
      EM.add_timer(2) {EM.stop} # avoid hanging in case of error

      EM.connect TestHost, TestPort, TestClient do |c|
        c.data_to { |d| data << d }
      end
    }

    assert_equal( "A" * 5000, data )
    File.unlink TestFilename
  end

  # EventMachine::Connection#send_file_data has a strict upper limit on the filesize it will work with.
  def test_send_large_file
    File.open( TestFilename, "w" ) {|f|
      f << ("A" * 1000000)
    }

    data = ''

    ex_class = RUBY_PLATFORM == 'java' ? NativeException : RuntimeError
    assert_raises( ex_class ) {
      EM.run {
        EM.start_server TestHost, TestPort, TestModule
        EM.add_timer(2) {EM.stop} # avoid hanging in case of error
        EM.connect TestHost, TestPort, TestClient do |c|
          c.data_to { |d| data << d }
        end
      }
    }

    File.unlink TestFilename
  end


  module StreamTestModule
    def post_init
      EM::Deferrable.future( stream_file_data(TestFilename)) {
        close_connection_after_writing
      }
    end
  end

  module ChunkStreamTestModule
    def post_init
      EM::Deferrable.future( stream_file_data(TestFilename, :http_chunks=>true)) {
        close_connection_after_writing
      }
    end
  end

  def test_stream_file_data
    File.open( TestFilename, "w" ) {|f|
      f << ("A" * 1000)
    }

    data = ''

    EM.run {
      EM.start_server TestHost, TestPort, StreamTestModule
      EM.add_timer(2) {EM.stop} # avoid hanging in case of error
      EM.connect TestHost, TestPort, TestClient do |c|
        c.data_to { |d| data << d }
      end
    }

    assert_equal( "A" * 1000, data )

    File.unlink TestFilename
  end

  def test_stream_chunked_file_data
    File.open( TestFilename, "w" ) {|f|
      f << ("A" * 1000)
    }

    data = ''

    EM.run {
      EM.start_server TestHost, TestPort, ChunkStreamTestModule
      EM.add_timer(2) {EM.stop} # avoid hanging in case of error
      EM.connect TestHost, TestPort, TestClient do |c|
        c.data_to { |d| data << d }
      end
    }

    assert_equal( "3e8\r\n#{"A" * 1000}\r\n0\r\n\r\n", data )

    File.unlink TestFilename
  end

  module BadFileTestModule
    def post_init
      de = stream_file_data( TestFilename+"..." )
      de.errback {|msg|
        send_data msg
        close_connection_after_writing
      }
    end
  end
  def test_stream_bad_file
    data = ''
    EM.run {
      EM.start_server TestHost, TestPort, BadFileTestModule
      EM.add_timer(2) {EM.stop} # avoid hanging in case of error
      EM.connect TestHost, TestPort, TestClient do |c|
        c.data_to { |d| data << d }
      end
    }

    assert_equal( "file not found", data )
  end

  def test_stream_large_file_data
    begin
      require 'fastfilereaderext'
    rescue LoadError
      return
    end
    File.open( TestFilename, "w" ) {|f|
      f << ("A" * 10000)
    }

    data = ''

    EM.run {
      EM.start_server TestHost, TestPort, StreamTestModule
      EM.add_timer(2) {EM.stop} # avoid hanging in case of error
      EM.connect TestHost, TestPort, TestClient do |c|
        c.data_to { |d| data << d }
      end
    }

    assert_equal( "A" * 10000, data )

    File.unlink TestFilename
  end

  def test_stream_large_chunked_file_data
    begin
      require 'fastfilereaderext'
    rescue LoadError
      return
    end
    File.open( TestFilename, "w" ) {|f|
      f << ("A" * 100000)
    }

    data = ''

    EM.run {
      EM.start_server TestHost, TestPort, ChunkStreamTestModule
      EM.add_timer(2) {EM.stop} # avoid hanging in case of error
      EM.connect TestHost, TestPort, TestClient do |c|
        c.data_to { |d| data << d }
      end
    }

    expected = [
      "4000\r\n#{"A" * 16384}\r\n" * 6,
      "6a0\r\n#{"A" * 0x6a0}\r\n",
      "0\r\n\r\n"
    ].join
    assert_equal( expected, data )

    File.unlink TestFilename
  end

end
