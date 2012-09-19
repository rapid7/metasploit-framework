#####################################################################
# tc_volume.rb
#
# Test case for the Windows::Volume module.
#####################################################################
require 'windows/volume'
require 'test/unit'

class TC_Windows_Volume < Test::Unit::TestCase
  include Windows::Volume

  def test_constants
    assert_equal(0, DRIVE_UNKNOWN)
    assert_equal(1, DRIVE_NO_ROOT_DIR)
    assert_equal(2, DRIVE_REMOVABLE)
    assert_equal(3, DRIVE_FIXED)
    assert_equal(4, DRIVE_REMOTE)
    assert_equal(5, DRIVE_CDROM)
    assert_equal(6, DRIVE_RAMDISK)
  end

  def test_method_constants
    assert_not_nil(DefineDosDevice)
    assert_not_nil(DeleteVolumeMountPoint)
    assert_not_nil(FindFirstVolume)
    assert_not_nil(FindFirstVolumeMountPoint)
    assert_not_nil(FindNextVolume)
    assert_not_nil(FindNextVolumeMountPoint)
    assert_not_nil(FindVolumeClose)
    assert_not_nil(FindVolumeMountPointClose)
    assert_not_nil(GetDriveType)
    assert_not_nil(GetLogicalDrives)
    assert_not_nil(GetLogicalDriveStrings)
    assert_not_nil(GetVolumeInformation)
    assert_not_nil(GetVolumeNameForVolumeMountPoint)
    assert_not_nil(GetVolumePathName)
    assert_not_nil(QueryDosDevice)
    assert_not_nil(SetVolumeLabel)
    assert_not_nil(SetVolumeMountPoint)
  end

  def test_get_volume_type
    assert(self.respond_to?(:get_volume_type, true))
    assert_nothing_raised{ get_volume_type }
    assert_kind_of(String, get_volume_type)
  end
end
