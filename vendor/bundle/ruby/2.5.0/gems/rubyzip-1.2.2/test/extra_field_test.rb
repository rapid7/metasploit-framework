require 'test_helper'

class ZipExtraFieldTest < MiniTest::Test
  def test_new
    extra_pure = ::Zip::ExtraField.new('')
    extra_withstr = ::Zip::ExtraField.new('foo')
    assert_instance_of(::Zip::ExtraField, extra_pure)
    assert_instance_of(::Zip::ExtraField, extra_withstr)
  end

  def test_unknownfield
    extra = ::Zip::ExtraField.new('foo')
    assert_equal(extra['Unknown'], 'foo')
    extra.merge('a')
    assert_equal(extra['Unknown'], 'fooa')
    extra.merge('barbaz')
    assert_equal(extra.to_s, 'fooabarbaz')
  end

  def test_ntfs
    str = "\x0A\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00\xC0\x81\x17\xE8B\xCE\xCF\x01\xC0\x81\x17\xE8B\xCE\xCF\x01\xC0\x81\x17\xE8B\xCE\xCF\x01"
    extra = ::Zip::ExtraField.new(str)
    assert(extra.member?('NTFS'))
    t = ::Zip::DOSTime.at(1_410_496_497.405178)
    assert_equal(t, extra['NTFS'].mtime)
    assert_equal(t, extra['NTFS'].atime)
    assert_equal(t, extra['NTFS'].ctime)
  end

  def test_merge
    str = "UT\x5\0\x3\250$\r@Ux\0\0"
    extra1 = ::Zip::ExtraField.new('')
    extra2 = ::Zip::ExtraField.new(str)
    assert(!extra1.member?('UniversalTime'))
    assert(extra2.member?('UniversalTime'))
    extra1.merge(str)
    assert_equal(extra1['UniversalTime'].mtime, extra2['UniversalTime'].mtime)
  end

  def test_length
    str = "UT\x5\0\x3\250$\r@Ux\0\0Te\0\0testit"
    extra = ::Zip::ExtraField.new(str)
    assert_equal(extra.local_size, extra.to_local_bin.size)
    assert_equal(extra.c_dir_size, extra.to_c_dir_bin.size)
    extra.merge('foo')
    assert_equal(extra.local_size, extra.to_local_bin.size)
    assert_equal(extra.c_dir_size, extra.to_c_dir_bin.size)
  end

  def test_to_s
    str = "UT\x5\0\x3\250$\r@Ux\0\0Te\0\0testit"
    extra = ::Zip::ExtraField.new(str)
    assert_instance_of(String, extra.to_s)

    s = extra.to_s
    extra.merge('foo')
    assert_equal(s.length + 3, extra.to_s.length)
  end

  def test_equality
    str = "UT\x5\0\x3\250$\r@"
    extra1 = ::Zip::ExtraField.new(str)
    extra2 = ::Zip::ExtraField.new(str)
    extra3 = ::Zip::ExtraField.new(str)
    assert_equal(extra1, extra2)

    extra2['UniversalTime'].mtime = ::Zip::DOSTime.now
    assert(extra1 != extra2)

    extra3.create('IUnix')
    assert(extra1 != extra3)

    extra1.create('IUnix')
    assert_equal(extra1, extra3)
  end
end
