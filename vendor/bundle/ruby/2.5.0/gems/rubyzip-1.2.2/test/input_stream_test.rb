require 'test_helper'

class ZipInputStreamTest < MiniTest::Test
  include AssertEntry

  class IOLike
    extend Forwardable

    def initialize(path, mode)
      @file = File.new(path, mode)
    end

    delegate ::Zip::File::IO_METHODS => :@file
  end

  def test_new
    zis = ::Zip::InputStream.new(TestZipFile::TEST_ZIP2.zip_name)
    assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
    assert_equal(true, zis.eof?)
    zis.close
  end

  def test_open_with_block
    ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name) do |zis|
      assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
      assert_equal(true, zis.eof?)
    end
  end

  def test_open_without_block
    zis = ::Zip::InputStream.open(File.new(TestZipFile::TEST_ZIP2.zip_name, 'rb'))
    assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
  end

  def test_open_buffer_with_block
    ::Zip::InputStream.open(File.new(TestZipFile::TEST_ZIP2.zip_name, 'rb')) do |zis|
      assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
      assert_equal(true, zis.eof?)
    end
  end

  def test_open_string_io_without_block
    string_io = ::StringIO.new(::File.read(TestZipFile::TEST_ZIP2.zip_name))
    zis = ::Zip::InputStream.open(string_io)
    assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
  end

  def test_open_string_io_with_block
    string_io = ::StringIO.new(::File.read(TestZipFile::TEST_ZIP2.zip_name))
    ::Zip::InputStream.open(string_io) do |zis|
      assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
      assert_equal(true, zis.eof?)
    end
  end

  def test_open_buffer_without_block
    zis = ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name)
    assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
  end

  def test_open_io_like_with_block
    ::Zip::InputStream.open(IOLike.new(TestZipFile::TEST_ZIP2.zip_name, 'rb')) do |zis|
      assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
      assert_equal(true, zis.eof?)
    end
  end

  def test_incomplete_reads
    ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name) do |zis|
      entry = zis.get_next_entry # longAscii.txt
      assert_equal(false, zis.eof?)
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[0], entry.name)
      assert !zis.gets.empty?
      assert_equal(false, zis.eof?)
      entry = zis.get_next_entry # empty.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[1], entry.name)
      assert_equal(0, entry.size)
      assert_nil(zis.gets)
      assert_equal(true, zis.eof?)
      entry = zis.get_next_entry # empty_chmod640.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[2], entry.name)
      assert_equal(0, entry.size)
      assert_nil(zis.gets)
      assert_equal(true, zis.eof?)
      entry = zis.get_next_entry # short.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[3], entry.name)
      assert !zis.gets.empty?
      entry = zis.get_next_entry # longBinary.bin
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[4], entry.name)
      assert !zis.gets.empty?
    end
  end

  def test_incomplete_reads_from_string_io
    string_io = ::StringIO.new(::File.read(TestZipFile::TEST_ZIP2.zip_name))
    ::Zip::InputStream.open(string_io) do |zis|
      entry = zis.get_next_entry # longAscii.txt
      assert_equal(false, zis.eof?)
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[0], entry.name)
      assert !zis.gets.empty?
      assert_equal(false, zis.eof?)
      entry = zis.get_next_entry # empty.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[1], entry.name)
      assert_equal(0, entry.size)
      assert_nil(zis.gets)
      assert_equal(true, zis.eof?)
      entry = zis.get_next_entry # empty_chmod640.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[2], entry.name)
      assert_equal(0, entry.size)
      assert_nil(zis.gets)
      assert_equal(true, zis.eof?)
      entry = zis.get_next_entry # short.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[3], entry.name)
      assert !zis.gets.empty?
      entry = zis.get_next_entry # longBinary.bin
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[4], entry.name)
      assert !zis.gets.empty?
    end
  end

  def test_read_with_number_of_bytes_returns_nil_at_eof
    ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name) do |zis|
      entry = zis.get_next_entry # longAscii.txt
      zis.read(entry.size)
      assert_equal(true, zis.eof?)
      assert_nil(zis.read(1))
      assert_nil(zis.read(1))
    end
  end

  def test_rewind
    ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name) do |zis|
      e = zis.get_next_entry
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[0], e.name)

      # Do a little reading
      buf = ''
      buf << zis.read(100)
      assert_equal(100, zis.pos)
      buf << (zis.gets || '')
      buf << (zis.gets || '')
      assert_equal(false, zis.eof?)

      zis.rewind

      buf2 = ''
      buf2 << zis.read(100)
      buf2 << (zis.gets || '')
      buf2 << (zis.gets || '')

      assert_equal(buf, buf2)

      zis.rewind
      assert_equal(false, zis.eof?)
      assert_equal(0, zis.pos)

      assert_entry(e.name, zis, e.name)
    end
  end

  def test_mix_read_and_gets
    ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name) do |zis|
      zis.get_next_entry
      assert_equal('#!/usr/bin/env ruby', zis.gets.chomp)
      assert_equal(false, zis.eof?)
      assert_equal('', zis.gets.chomp)
      assert_equal(false, zis.eof?)
      assert_equal('$VERBOSE =', zis.read(10))
      assert_equal(false, zis.eof?)
    end
  end

  def test_ungetc
    ::Zip::InputStream.open(TestZipFile::TEST_ZIP2.zip_name) do |zis|
      zis.get_next_entry
      first_line = zis.gets.chomp
      first_line.reverse.bytes.each { |b| zis.ungetc(b) }
      assert_equal('#!/usr/bin/env ruby', zis.gets.chomp)
      assert_equal('$VERBOSE =', zis.read(10))
    end
  end
end
