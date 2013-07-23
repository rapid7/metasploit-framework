# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptString do
  valid_values = [
      { :value => 'foo',    :normalized => 'foo'     },
      { :value => "file:#{File.expand_path('string_list.txt',FILE_FIXTURES_PATH)}",:normalized => "foo\nbar\nbaz" },
  ]
  invalid_values = [
      # Non-string values
      { :value => true},
      { :value => 5 },
      { :value => []},
      { :value => [1,2]},
      { :value => {}},
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'string'
end