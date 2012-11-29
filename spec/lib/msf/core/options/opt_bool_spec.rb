
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptBool do
  valid_values =
    [
      ["true",  true ],
      ["yes",   true ],
      ["1",     true ],
      ["false", false],
      ["no",    false],
      ["0",     false],
    ]
  invalid_values =
    [ "yer mom", "123", "012" ]
  it_behaves_like "an option", valid_values, invalid_values
end

