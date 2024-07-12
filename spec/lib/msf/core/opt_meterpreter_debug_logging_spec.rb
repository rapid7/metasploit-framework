# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptMeterpreterDebugLogging do
  valid_values = [
    { value: 'rpath:C:/log.txt', normalized: 'rpath:C:/log.txt' },
    { value: 'rpath:/tmp/log.txt', normalized: 'rpath:/tmp/log.txt' },
    { value: 'rpath:./log.log', normalized: 'rpath:./log.log' },
    { value: ' rpath:./log.log ', normalized: ' rpath:./log.log ' },
    { value: '', normalized: '' },
    { value: '  ', normalized: '  ' }
  ]
  invalid_values = [
    { value: 'rpath', normalized: 'rpath' },
    { value: 'C:', normalized: 'C:' },
    { value: 'C', normalized: 'C' },
    { value: 'rpath:C', normalized: 'rpath:C' }
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'meterpreterdebuglogging'

  describe '.parse_logging_options' do
    [
      { value: nil, expected: {} },
      { value: '', expected: {} },
      { value: '  ', expected: {} },
      { value: 'rpath:./file', expected: { rpath: './file' } },
      { value: '  rpath:C:/file  ', expected: { rpath: 'C:/file' } },
    ].each do |test|
      it "parses #{test[:value]} as #{test[:expected]}" do
        expect(described_class.parse_logging_options(test[:value])).to eq test[:expected]
      end
    end
  end
end
