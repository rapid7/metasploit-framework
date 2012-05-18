require 'rdoc/test_case'

class TestRDocRdInline < RDoc::TestCase

  def setup
    super

    @inline = RDoc::RD::Inline.new '+text+', 'text'
  end

  def test_class_new
    inline = RDoc::RD::Inline.new @inline

    refute_equal inline.rdoc, inline.reference
  end

  def test_initialize
    inline = RDoc::RD::Inline.new 'text'

    assert_equal inline.rdoc, inline.reference
    refute_same  inline.rdoc, inline.reference
  end

  def test_initialize_inline
    inline = RDoc::RD::Inline.new @inline

    assert_equal '+text+', inline.rdoc
    assert_equal 'text',   inline.reference
  end

  def test_append_inline
    out = @inline.append @inline

    assert_same @inline, out

    assert_equal '+text++text+', @inline.rdoc
    assert_equal 'texttext',     @inline.reference
  end

  def test_append_string
    @inline.append ' more'

    assert_equal '+text+ more', @inline.rdoc
    assert_equal 'text more',   @inline.reference
  end

  def test_equals2
    assert_equal @inline, RDoc::RD::Inline.new('+text+', 'text')
    refute_equal @inline, RDoc::RD::Inline.new('+text+', 'other')
    refute_equal @inline, RDoc::RD::Inline.new('+other+', 'text')
    refute_equal @inline, Object.new
  end

  def test_inspect
    assert_equal '(inline: +text+)', @inline.inspect
  end

  def test_to_s
    assert_equal '+text+', @inline.to_s
  end

end

