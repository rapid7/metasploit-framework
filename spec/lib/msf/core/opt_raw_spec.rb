# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

RSpec.describe Msf::OptRaw do

  valid_values = [
      { :value => 'foo',    :normalized => 'foo'     },
      { :value => "file:#{File.expand_path('string_list.txt',FILE_FIXTURES_PATH)}",:normalized => "foo\nbar\nbaz" }
  ]
  invalid_values = []

  it_behaves_like "an option", valid_values, invalid_values, 'raw'
end
