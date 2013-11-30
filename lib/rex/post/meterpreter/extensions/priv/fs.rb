# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Priv

###
#
# This class provides an interface to modifying the file system to avoid
# detection, such as by modifying extended file system attributes.
#
###
class Fs

  #
  # Initializes the file system subsystem of the privilege escalation
  # extension.
  #
  def initialize(client)
    self.client = client
  end

  #
  # Returns a hash of the Modified, Accessed, Created, and Entry Modified
  # values for the specified file path.
  #
  def get_file_mace(file_path)
    request = Packet.create_request('priv_fs_get_file_mace')

    request.add_tlv(TLV_TYPE_FS_FILE_PATH, file_path)

    response = client.send_request(request)

    # Return the hash of times associated with the MACE values
    begin
      return {
        'Modified'       => Time.at(response.get_tlv_value(TLV_TYPE_FS_FILE_MODIFIED)),
        'Accessed'       => Time.at(response.get_tlv_value(TLV_TYPE_FS_FILE_ACCESSED)),
        'Created'        => Time.at(response.get_tlv_value(TLV_TYPE_FS_FILE_CREATED)),
        'Entry Modified' => Time.at(response.get_tlv_value(TLV_TYPE_FS_FILE_EMODIFIED))
      }
    rescue RangeError
      raise RangeError, "Invalid MACE values"
    end
  end

  #
  # Sets the Modified, Accessed, Created, and Entry Modified attributes of
  # the specified file path.  If a nil is supplied for a value, it will not
  # be modified.  Otherwise, the times should be instances of the Time class.
  #
  def set_file_mace(file_path, modified = nil, accessed = nil, created = nil,
    entry_modified = nil)
    request = Packet.create_request('priv_fs_set_file_mace')

    request.add_tlv(TLV_TYPE_FS_FILE_PATH, file_path)
    request.add_tlv(TLV_TYPE_FS_FILE_MODIFIED, modified.to_i) if (modified)
    request.add_tlv(TLV_TYPE_FS_FILE_ACCESSED, accessed.to_i) if (accessed)
    request.add_tlv(TLV_TYPE_FS_FILE_CREATED, created.to_i) if (created)
    request.add_tlv(TLV_TYPE_FS_FILE_EMODIFIED, entry_modified.to_i) if (entry_modified)

    client.send_request(request)

    true
  end

  #
  # Sets the MACE attributes of the specified target_file_path to the MACE
  # attributes of the source_file_path.
  #
  def set_file_mace_from_file(target_file_path, source_file_path)
    request = Packet.create_request('priv_fs_set_file_mace_from_file')

    request.add_tlv(TLV_TYPE_FS_FILE_PATH, target_file_path)
    request.add_tlv(TLV_TYPE_FS_SRC_FILE_PATH, source_file_path)

    client.send_request(request)

    true
  end

  #
  # Sets the MACE values to the minimum threshold that will cause them to not
  # be displayed by most all products for a file.
  #
  def blank_file_mace(file_path)
    request = Packet.create_request('priv_fs_blank_file_mace')

    request.add_tlv(TLV_TYPE_FS_FILE_PATH, file_path)

    client.send_request(request)

    true
  end

  #
  # Recursively set the MACE values to the minimum threshold for the supplied
  # directory.
  #
  def blank_directory_mace(dir_path)
    request = Packet.create_request('priv_fs_blank_directory_mace')

    request.add_tlv(TLV_TYPE_FS_FILE_PATH, dir_path)

    client.send_request(request)

    true
  end

protected

  attr_accessor :client # :nodoc:

end

end; end; end; end; end
