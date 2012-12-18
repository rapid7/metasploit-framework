
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptPort do
  valid_values = [
    { :pending => "Redmine #7535", :value => "0",    :normalized => 0     },
    { :pending => "Redmine #7535", :value => "65536",:normalized => 65536 },
    { :pending => "Redmine #7535", :value => "80",   :normalized => 80    },
  ]
  invalid_values = [
    { :value => "yer mom", },
    { :value => "0.1",     },
    { :value => "-1",      },
    { :value => "65536",   },
  ]

  it_behaves_like "an option", valid_values, invalid_values
end

