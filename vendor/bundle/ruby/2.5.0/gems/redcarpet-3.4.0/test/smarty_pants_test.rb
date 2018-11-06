# coding: UTF-8
require 'test_helper'

class SmartyPantsTest < Redcarpet::TestCase
  def setup
    @pants = Redcarpet::Render::SmartyPants
  end

  def test_that_smart_converts_single_quotes_in_words_that_end_in_re
    markdown = @pants.render("<p>They're not for sale.</p>")
    assert_equal "<p>They&rsquo;re not for sale.</p>", markdown
  end

  def test_that_smart_converts_single_quotes_in_words_that_end_in_ll
    markdown = @pants.render("<p>Well that'll be the day</p>")
    assert_equal "<p>Well that&rsquo;ll be the day</p>", markdown
  end

  def test_that_smart_converts_double_quotes_to_curly_quotes
    rd = @pants.render(%(<p>"Quoted text"</p>))
    assert_equal %(<p>&ldquo;Quoted text&rdquo;</p>), rd
  end

  def test_that_smart_gives_ve_suffix_a_rsquo
    rd = @pants.render("<p>I've been meaning to tell you ..</p>")
    assert_equal "<p>I&rsquo;ve been meaning to tell you ..</p>", rd
  end

  def test_that_smart_gives_m_suffix_a_rsquo
    rd = @pants.render("<p>I'm not kidding</p>")
    assert_equal "<p>I&rsquo;m not kidding</p>", rd
  end

  def test_that_smart_gives_d_suffix_a_rsquo
    rd = @pants.render("<p>what'd you say?</p>")
    assert_equal "<p>what&rsquo;d you say?</p>", rd
  end

  def test_that_backticks_are_preserved
    rd = @pants.render("<p>single `backticks` in HTML should be preserved</p>")
    assert_equal "<p>single `backticks` in HTML should be preserved</p>", rd
  end

  def test_that_smart_converts_trailing_single_quotes_to_curly_quotes
    rd = @pants.render("<p>Hopin' that this bug gets some fixin'.</p>")
    assert_equal "<p>Hopin&rsquo; that this bug gets some fixin&rsquo;.</p>", rd
  end

  def test_that_is_not_confused_by_fractions
    rd = @pants.render('I am 1/4... of the way to 1/4/2000')
    assert_equal "I am &frac14;&hellip; of the way to 1/4/2000", rd
  end

  def test_that_smart_converts_multiple_single_quotes
    rd = @pants.render(%(<p>'First' and 'second' and 'third'</p>))
    assert_equal %(<p>&lsquo;First&rsquo; and &lsquo;second&rsquo; and &lsquo;third&rsquo;</p>), rd
  end
end
