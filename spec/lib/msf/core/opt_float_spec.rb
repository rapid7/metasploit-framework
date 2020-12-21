# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

RSpec.describe Msf::OptFloat do
  valid_values = [
    { :value => "1",    :normalized => 1.0 },
    { :value => "1.1",  :normalized => 1.1 },
    { :value => "0",    :normalized => 0.0 },
    { :value => "-1",   :normalized => -1.0 },
    { :value => "01",   :normalized => 1.0 },
    { :value => "0xff", :normalized => 255.0 },
  ]
  invalid_values = [
    { :value => "0xblah",  },
    { :value => "-12cat",  },
    { :value => "covfefe", },
    { :value => "NaN",     },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'float'
end


