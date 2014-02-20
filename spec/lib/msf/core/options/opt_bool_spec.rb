# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptBool do
  valid_values = [
    { :value => "true",  :normalized => true  },
    { :value => "yes",   :normalized => true  },
    { :value => "1",     :normalized => true  },
    { :value => "false", :normalized => false },
    { :value => "no",    :normalized => false },
    { :value => "0",     :normalized => false },
  ]
  invalid_values = [
    { :value => "yer mom" },
    { :value => "012"     },
    { :value => "123"     },
  ]
  it_behaves_like "an option", valid_values, invalid_values, 'bool'

end

