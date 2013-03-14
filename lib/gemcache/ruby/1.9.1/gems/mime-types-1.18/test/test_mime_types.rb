$LOAD_PATH.unshift("#{File.dirname(__FILE__)}/../lib") if __FILE__ == $0

require 'mime/types'

class TestMIME_Types < MiniTest::Unit::TestCase #:nodoc:
  def test_class_index_1
    text_plain = MIME::Type.new('text/plain') do |t|
      t.encoding = '8bit'
      t.extensions = %w(asc txt c cc h hh cpp hpp dat hlp)
    end
    text_plain_vms = MIME::Type.new('text/plain') do |t|
      t.encoding = '8bit'
      t.extensions = %w(doc)
      t.system = 'vms'
    end

    assert_equal(MIME::Types['text/plain'], [text_plain, text_plain_vms])
  end

  def test_class_index_2
    tst_bmp = MIME::Types["image/x-bmp"] +
      MIME::Types["image/vnd.wap.wbmp"] + MIME::Types["image/x-win-bmp"]

    assert_equal(tst_bmp.sort, MIME::Types[/bmp$/].sort)

    MIME::Types['image/bmp'][0].system = RUBY_PLATFORM

    assert_equal([MIME::Type.from_array('image/x-bmp', ['bmp'])],
                 MIME::Types[/bmp$/, { :platform => true }])
  end

  def test_class_index_3
    assert(MIME::Types['text/vnd.fly', { :complete => true }].empty?)
    assert(!MIME::Types['text/plain', { :complete => true} ].empty?)
  end

  def _test_class_index_extensions
    raise NotImplementedError, 'Need to write test_class_index_extensions'
  end

  def test_class_add
    eruby = MIME::Type.new("application/x-eruby") do |t|
      t.extensions = "rhtml"
      t.encoding = "8bit"
    end

    MIME::Types.add(eruby)

    assert_equal(MIME::Types['application/x-eruby'], [eruby])
  end

  def _test_class_add_type_variant
    raise NotImplementedError, 'Need to write test_class_add_type_variant'
  end

  def test_class_type_for
    assert_equal(MIME::Types.type_for('xml').sort, [ MIME::Types['text/xml'], MIME::Types['application/xml'] ].sort)
    assert_equal(MIME::Types.type_for('gif'), MIME::Types['image/gif'])
    MIME::Types['image/gif'][0].system = RUBY_PLATFORM
    assert_equal(MIME::Types.type_for('gif', true), MIME::Types['image/gif'])
    assert(MIME::Types.type_for('zzz').empty?)
  end

  def test_class_of
    assert_equal(MIME::Types.of('xml').sort, [ MIME::Types['text/xml'], MIME::Types['application/xml'] ].sort)
    assert_equal(MIME::Types.of('gif'), MIME::Types['image/gif'])
    MIME::Types['image/gif'][0].system = RUBY_PLATFORM
    assert_equal(MIME::Types.of('gif', true), MIME::Types['image/gif'])
    assert(MIME::Types.of('zzz').empty?)
  end

  def _test_add
    raise NotImplementedError, 'Need to write test_add'
  end

  def _test_add_type_variant
    raise NotImplementedError, 'Need to write test_add_type_variant'
  end

  def _test_data_version
    raise NotImplementedError, 'Need to write test_data_version'
  end

  def _test_index
    raise NotImplementedError, 'Need to write test_index'
  end

  def _test_index_extensions
    raise NotImplementedError, 'Need to write test_index_extensions'
  end

  def _test_of
    raise NotImplementedError, 'Need to write test_of'
  end

  def _test_type_for
    raise NotImplementedError, 'Need to write test_type_for'
  end
end
