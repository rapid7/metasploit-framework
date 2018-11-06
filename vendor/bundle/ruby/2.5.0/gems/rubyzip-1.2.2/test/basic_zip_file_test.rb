require 'test_helper'

class BasicZipFileTest < MiniTest::Test
  include AssertEntry

  def setup
    @zip_file = ::Zip::File.new(TestZipFile::TEST_ZIP2.zip_name)
    @testEntryNameIndex = 0
  end

  def test_entries
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.sort,
                 @zip_file.entries.entries.sort.map { |e| e.name })
  end

  def test_each
    count = 0
    visited = {}
    @zip_file.each do |entry|
      assert(TestZipFile::TEST_ZIP2.entry_names.include?(entry.name))
      assert(!visited.include?(entry.name))
      visited[entry.name] = nil
      count = count.succ
    end
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.length, count)
  end

  def test_foreach
    count = 0
    visited = {}
    ::Zip::File.foreach(TestZipFile::TEST_ZIP2.zip_name) do |entry|
      assert(TestZipFile::TEST_ZIP2.entry_names.include?(entry.name))
      assert(!visited.include?(entry.name))
      visited[entry.name] = nil
      count = count.succ
    end
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.length, count)
  end

  def test_get_input_stream
    count = 0
    visited = {}
    @zip_file.each do |entry|
      assert_entry(entry.name, @zip_file.get_input_stream(entry), entry.name)
      assert(!visited.include?(entry.name))
      visited[entry.name] = nil
      count = count.succ
    end
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.length, count)
  end

  def test_get_input_stream_block
    fileAndEntryName = @zip_file.entries.first.name
    @zip_file.get_input_stream(fileAndEntryName) do |zis|
      assert_entry_contents_for_stream(fileAndEntryName,
                                       zis,
                                       fileAndEntryName)
    end
  end
end
