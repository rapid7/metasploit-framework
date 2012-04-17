require 'test_helper'

module FunnyFilter
  def make_funny(input)
    'LOL'
  end

  def cite_funny(input)
    "LOL: #{input}"
  end

  def add_smiley(input, smiley = ":-)")
    "#{input} #{smiley}"
  end

  def add_tag(input, tag = "p", id = "foo")
    %|<#{tag} id="#{id}">#{input}</#{tag}>|
  end

  def paragraph(input)
    "<p>#{input}</p>"
  end

  def link_to(name, url)
    %|<a href="#{url}">#{name}</a>|
  end

end

class OutputTest < Test::Unit::TestCase
  include Liquid

  def setup
    @assigns = {
      'best_cars' => 'bmw',
      'car' => {'bmw' => 'good', 'gm' => 'bad'}
      }
  end

  def test_variable
    text = %| {{best_cars}} |

    expected = %| bmw |
    assert_equal expected, Template.parse(text).render(@assigns)
  end

  def test_variable_traversing
    text = %| {{car.bmw}} {{car.gm}} {{car.bmw}} |

    expected = %| good bad good |
    assert_equal expected, Template.parse(text).render(@assigns)
  end               

  def test_variable_piping
    text = %( {{ car.gm | make_funny }} )
    expected = %| LOL |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_variable_piping_with_input
    text = %( {{ car.gm | cite_funny }} )
    expected = %| LOL: bad |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_variable_piping_with_args
    text = %! {{ car.gm | add_smiley : ':-(' }} !
    expected = %| bad :-( |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_variable_piping_with_no_args
    text = %! {{ car.gm | add_smiley }} !
    expected = %| bad :-) |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_multiple_variable_piping_with_args
    text = %! {{ car.gm | add_smiley : ':-(' | add_smiley : ':-('}} !
    expected = %| bad :-( :-( |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_variable_piping_with_args
    text = %! {{ car.gm | add_tag : 'span', 'bar'}} !
    expected = %| <span id="bar">bad</span> |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_variable_piping_with_variable_args
    text = %! {{ car.gm | add_tag : 'span', car.bmw}} !
    expected = %| <span id="good">bad</span> |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_multiple_pipings
    text = %( {{ best_cars | cite_funny | paragraph }} )
    expected = %| <p>LOL: bmw</p> |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end

  def test_link_to
    text = %( {{ 'Typo' | link_to: 'http://typo.leetsoft.com' }} )
    expected = %| <a href="http://typo.leetsoft.com">Typo</a> |

    assert_equal expected, Template.parse(text).render(@assigns, :filters => [FunnyFilter])
  end
end # OutputTest