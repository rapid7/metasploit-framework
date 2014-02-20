# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptPort do
  valid_values = [
    { :value => "0",    :normalized => 0     },
    { :value => "65535",:normalized => 65535 },
    { :value => "80",   :normalized => 80    },
  ]
  invalid_values = [
    { :value => "yer mom", },
    { :value => "0.1",     },
    { :value => "-1",      },
    { :value => "65536",   },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'port'
end

