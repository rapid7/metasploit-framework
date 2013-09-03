# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptInt do
  valid_values = [
    { :value => "1",    :normalized => 1  },
    { :value => "10",   :normalized => 10 },
    { :value => "0",    :normalized => 0  },
    { :value => "0x10", :normalized => 16 },
    { :value => "0x0a", :normalized => 10 },
    { :value => "0x0A", :normalized => 10 },
    { :value => "0xFf", :normalized => 255},
    { :value => "-1",   :normalized => -1 },
  ]
  invalid_values = [
    { :value => "yer mom", },
    { :value => "0.1",     },
    { :value => "0xG",     },
    { :value => "FF",      },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'integer'
end


