require 'spec_helper'
require 'windows_error/win32'

describe WindowsError::Win32 do

  describe '#find_by_retval' do

    it 'raises an argument error when passed an invalid value' do
      expect { WindowsError::Win32.find_by_retval('foo') }.to raise_error ArgumentError, 'Invalid Return Code!'
    end

    it 'returns an array with the error_codes for that return value' do
      expect(WindowsError::Win32.find_by_retval(0x00000008)).to match_array([WindowsError::Win32::ERROR_NOT_ENOUGH_MEMORY])
    end

    it 'returns an empty array if there is no match' do
      expect(WindowsError::Win32.find_by_retval(0x99999999)).to match_array([])
    end
  end
end