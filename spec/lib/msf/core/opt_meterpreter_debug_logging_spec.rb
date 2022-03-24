# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptMeterpreterDebugLogging do
  valid_values = [
    { value: 'rpath:C:/log.txt', normalized: 'rpath:C:/log.txt' },
    { value: 'rpath:/tmp/log.txt', normalized: 'rpath:/tmp/log.txt' },
    { value: 'rpath:./log.log', normalized: 'rpath:./log.log' },
    { value: ' rpath:./log.log ', normalized: ' rpath:./log.log ' }
  ]
  invalid_values = [
    { value: 'rpath', normalized: 'rpath' },
    { value: 'C:', normalized: 'C:' },
    { value: 'C', normalized: 'C' },
    { value: 'rpath:C', normalized: 'rpath:C' }
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'meterpreterdebuglogging'
end
