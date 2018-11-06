require 'spec_helper'
require 'windows_error/nt_status'

describe WindowsError::NTStatus do

  describe '#find_by_retval' do

    it 'raises an argument error when passed an invalid value' do
      expect { WindowsError::NTStatus.find_by_retval('foo') }.to raise_error ArgumentError, 'Invalid Return Code!'
    end

    it 'returns an array with the error_codes for that return value' do
      expect(WindowsError::NTStatus.find_by_retval(0x00000102)).to match_array([WindowsError::NTStatus::STATUS_TIMEOUT])
    end

    it 'returns multiple entries if there are more than one match' do
      expect(WindowsError::NTStatus.find_by_retval(0x00000000)).to match_array([WindowsError::NTStatus::STATUS_SUCCESS, WindowsError::NTStatus::STATUS_WAIT_0])
    end

    it 'returns an empty array if there is no match' do
      expect(WindowsError::NTStatus.find_by_retval(0x99999999)).to match_array([])
    end
  end
end