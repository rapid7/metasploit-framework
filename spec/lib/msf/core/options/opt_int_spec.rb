
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptInt do
  valid_values = [
    { :value => "1",    :normalized => 1  },
    { :value => "10",   :normalized => 10 },
    { :value => "0",    :normalized => 0  },
    { :value => "0x10", :normalized => 16 },
    { :pending => "Redmine #7540", :value => "-1", :normalized => -1 }
  ]
  invalid_values = [
    { :pending => "Redmine #7539", :value => "yer mom", },
    { :pending => "Redmine #7539", :value => "0.1",     },
  ]

  it_behaves_like "an option", valid_values, invalid_values
end


