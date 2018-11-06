require 'helper'

class TestAfm < Minitest::Test
  
  def setup
    @font = AFM::Font.new(File.join(File.dirname(__FILE__), 'fixtures', 'Vera.afm'))
  end  
  
  def test_should_set_metadata
    assert_equal "BitstreamVeraSans-Roman", @font.metadata['FontName']
    assert_equal "BitstreamVeraSans-Roman", @font['FontName']
  end

  def test_should_set_char_metrics
    assert_equal 400, @font.char_metrics['exclam'][:wx]
    assert_equal [85, -131, 310, 758], @font.char_metrics['parenleft'][:boundingbox]
  end

  def test_should_set_char_metrics_by_code
    assert_equal 400, @font.char_metrics_by_code[33][:wx]
    assert_equal [85, -131, 310, 758], @font.char_metrics_by_code[40][:boundingbox]
  end
  
  def test_should_get_char_metrics_by_char
    assert_equal 400, @font.metrics_for("!")[:wx]
  end
  
  def test_open_font_with_alternative_method
    assert !AFM::Font.from_file(File.join(File.dirname(__FILE__), 'fixtures', 'Vera.afm')).nil?
  end
    
end
