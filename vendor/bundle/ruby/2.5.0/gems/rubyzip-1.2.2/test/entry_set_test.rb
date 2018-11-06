require 'test_helper'

class ZipEntrySetTest < MiniTest::Test
  ZIP_ENTRIES = [
    ::Zip::Entry.new('zipfile.zip', 'name1', 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name3', 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name2', 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name4', 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name5', 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name6', 'comment1')
  ]

  def setup
    @zipEntrySet = ::Zip::EntrySet.new(ZIP_ENTRIES)
  end

  def teardown
    ::Zip.reset!
  end

  def test_include
    assert(@zipEntrySet.include?(ZIP_ENTRIES.first))
    assert(!@zipEntrySet.include?(::Zip::Entry.new('different.zip', 'different', 'aComment')))
  end

  def test_size
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.length)
    @zipEntrySet << ::Zip::Entry.new('a', 'b', 'c')
    assert_equal(ZIP_ENTRIES.size + 1, @zipEntrySet.length)
  end

  def test_add
    zes = ::Zip::EntrySet.new
    entry1 = ::Zip::Entry.new('zf.zip', 'name1')
    entry2 = ::Zip::Entry.new('zf.zip', 'name2')
    zes << entry1
    assert(zes.include?(entry1))
    zes.push(entry2)
    assert(zes.include?(entry2))
  end

  def test_delete
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
    entry = @zipEntrySet.delete(ZIP_ENTRIES.first)
    assert_equal(ZIP_ENTRIES.size - 1, @zipEntrySet.size)
    assert_equal(ZIP_ENTRIES.first, entry)

    entry = @zipEntrySet.delete(ZIP_ENTRIES.first)
    assert_equal(ZIP_ENTRIES.size - 1, @zipEntrySet.size)
    assert_nil(entry)
  end

  def test_each
    # Used each instead each_with_index due the bug in jRuby
    count = 0
    @zipEntrySet.each do |entry|
      assert(ZIP_ENTRIES.include?(entry))
      count += 1
    end
    assert_equal(ZIP_ENTRIES.size, count)
  end

  def test_entries
    assert_equal(ZIP_ENTRIES, @zipEntrySet.entries)
  end

  def test_find_entry
    entries = [::Zip::Entry.new('zipfile.zip', 'MiXeDcAsEnAmE', 'comment1')]

    ::Zip.case_insensitive_match = true
    zipEntrySet = ::Zip::EntrySet.new(entries)
    assert_equal(entries[0], zipEntrySet.find_entry('MiXeDcAsEnAmE'))
    assert_equal(entries[0], zipEntrySet.find_entry('mixedcasename'))

    ::Zip.case_insensitive_match = false
    zipEntrySet = ::Zip::EntrySet.new(entries)
    assert_equal(entries[0], zipEntrySet.find_entry('MiXeDcAsEnAmE'))
    assert_nil(zipEntrySet.find_entry('mixedcasename'))
  end

  def test_entries_with_sort
    ::Zip.sort_entries = true
    assert_equal(ZIP_ENTRIES.sort, @zipEntrySet.entries)
    ::Zip.sort_entries = false
    assert_equal(ZIP_ENTRIES, @zipEntrySet.entries)
  end

  def test_entries_sorted_in_each
    ::Zip.sort_entries = true
    arr = []
    @zipEntrySet.each do |entry|
      arr << entry
    end
    assert_equal(ZIP_ENTRIES.sort, arr)
  end

  def test_compound
    newEntry = ::Zip::Entry.new('zf.zip', 'new entry', "new entry's comment")
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
    @zipEntrySet << newEntry
    assert_equal(ZIP_ENTRIES.size + 1, @zipEntrySet.size)
    assert(@zipEntrySet.include?(newEntry))

    @zipEntrySet.delete(newEntry)
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
  end

  def test_dup
    copy = @zipEntrySet.dup
    assert_equal(@zipEntrySet, copy)

    # demonstrate that this is a deep copy
    copy.entries[0].name = 'a totally different name'
    assert(@zipEntrySet != copy)
  end

  def test_parent
    entries = [
      ::Zip::Entry.new('zf.zip', 'a/'),
      ::Zip::Entry.new('zf.zip', 'a/b/'),
      ::Zip::Entry.new('zf.zip', 'a/b/c/')
    ]
    entrySet = ::Zip::EntrySet.new(entries)

    assert_nil(entrySet.parent(entries[0]))
    assert_equal(entries[0], entrySet.parent(entries[1]))
    assert_equal(entries[1], entrySet.parent(entries[2]))
  end

  def test_glob
    res = @zipEntrySet.glob('name[2-4]')
    assert_equal(3, res.size)
    assert_equal(ZIP_ENTRIES[1, 3].sort, res.sort)
  end

  def test_glob2
    entries = [
      ::Zip::Entry.new('zf.zip', 'a/'),
      ::Zip::Entry.new('zf.zip', 'a/b/b1'),
      ::Zip::Entry.new('zf.zip', 'a/b/c/'),
      ::Zip::Entry.new('zf.zip', 'a/b/c/c1')
    ]
    entrySet = ::Zip::EntrySet.new(entries)

    assert_equal(entries[0, 1], entrySet.glob('*'))
    # assert_equal(entries[FIXME], entrySet.glob("**"))
    # res = entrySet.glob('a*')
    # assert_equal(entries.size, res.size)
    # assert_equal(entrySet.map { |e| e.name }, res.map { |e| e.name })
  end

  def test_glob3
    entries = [
      ::Zip::Entry.new('zf.zip', 'a/a'),
      ::Zip::Entry.new('zf.zip', 'a/b'),
      ::Zip::Entry.new('zf.zip', 'a/c')
    ]
    entrySet = ::Zip::EntrySet.new(entries)

    assert_equal(entries[0, 2].sort, entrySet.glob('a/{a,b}').sort)
  end
end
