# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

RSpec.describe Msf::OptAddressLocal do
  valid_values = [
    { :value => "192.0.2.0/24", :normalized => "192.0.2.0/24" },
    { :value => "192.0.2.0",    :normalized => "192.0.2.0" },
    { :value => "127.0.0.1",    :normalized => "127.0.0.1" },
    { :value => "2001:db8::",   :normalized => "2001:db8::" },
    { :value => "::1",          :normalized => "::1" }
  ]
  
  invalid_values = [
    # Too many dots
    { :value => "192.0.2.0.0" },
    # Not enough
    { :value => "192.0.2" },
    # Non-string values
    { :value => true},
    { :value => 5 },
    { :value => []},
    { :value => [1,2]},
    { :value => {}},
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'address'



end


