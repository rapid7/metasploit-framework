require 'test_helper'

module SecurityFilter
  def add_one(input)
    "#{input} + 1"
  end
end

class SecurityTest < Test::Unit::TestCase
  include Liquid

  def test_no_instance_eval
    text = %( {{ '1+1' | instance_eval }} )
    expected = %| 1+1 |

    assert_equal expected, Template.parse(text).render(@assigns)
  end

  def test_no_existing_instance_eval
    text = %( {{ '1+1' | __instance_eval__ }} )
    expected = %| 1+1 |

    assert_equal expected, Template.parse(text).render(@assigns)
  end


  def test_no_instance_eval_after_mixing_in_new_filter
    text = %( {{ '1+1' | instance_eval }} )
    expected = %| 1+1 |

    assert_equal expected, Template.parse(text).render(@assigns)
  end


  def test_no_instance_eval_later_in_chain
    text = %( {{ '1+1' | add_one | instance_eval }} )
    expected = %| 1+1 + 1 |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => SecurityFilter)
  end
end # SecurityTest
