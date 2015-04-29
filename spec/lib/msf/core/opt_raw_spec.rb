# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptRaw do

  valid_values = [
      { :value => 'foo',    :normalized => 'foo'     }
  ]
  invalid_values = []

  it_behaves_like "an option", valid_values, invalid_values, 'raw'
end
