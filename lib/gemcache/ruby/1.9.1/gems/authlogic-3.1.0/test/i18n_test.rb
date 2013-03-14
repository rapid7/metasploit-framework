require 'test_helper'

class I18nTest < ActiveSupport::TestCase
  def test_uses_authlogic_as_scope_by_default
    assert_equal :authlogic, Authlogic::I18n.scope
  end
  
  def test_can_set_scope
    assert_nothing_raised { Authlogic::I18n.scope = [:a, :b] }
    assert_equal [:a, :b], Authlogic::I18n.scope
    Authlogic::I18n.scope = :authlogic
  end
  
  def test_uses_built_in_translator_by_default
    assert_equal Authlogic::I18n::Translator, Authlogic::I18n.translator.class
  end
  
  def test_can_set_custom_translator
    old_translator = Authlogic::I18n.translator
    
    assert_nothing_raised do
      Authlogic::I18n.translator = Class.new do
        def translate(key, options = {})
          "Translated: #{key}"
        end
      end.new
    end

    assert_equal "Translated: x", Authlogic::I18n.translate(:x)
    
    Authlogic::I18n.translator = old_translator
  end
end
