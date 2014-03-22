# -*- coding: binary -*-

require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module ProcessSubsystem

###
#
# Interacts with loading, unloading, enumerating, and querying
# image files in the context of a given process.
#
###
class Image

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the image instance.
  #
  def initialize(process)
    self.process = process
  end

  #
  # Returns the image base address associated with the supplied image name.
  #
  def [](key)
    each_image { |i|
      if (i['name'].downcase == key.downcase)
        return i['base']
      end
    }

    return nil
  end

  #
  # Loads an image file into the context of the process.
  #
  def load(image_path)
    request = Packet.create_request('stdapi_sys_process_image_load')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_IMAGE_FILE_PATH, image_path)

    response = process.client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_IMAGE_BASE)
  end

  #
  # Returns the address of the procedure that is found in the supplied
  # library.
  #
  def get_procedure_address(image_file, procedure)
    request = Packet.create_request('stdapi_sys_process_image_get_proc_address')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_IMAGE_FILE, image_file)
    request.add_tlv(TLV_TYPE_PROCEDURE_NAME, procedure)

    response = process.client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_PROCEDURE_ADDRESS)
  end

  #
  # Unloads an image file that is loaded into the address space of the
  # process by its base address.
  #
  def unload(base)
    request = Packet.create_request('stdapi_sys_process_image_unload')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_IMAGE_BASE, base)

    response = process.client.send_request(request)

    return true
  end

  #
  # Enumerates through each image in the process.
  #
  def each_image(&block)
    get_images.each(&block)
  end

  #
  # Returns an array of images in the process with hash objects that
  # have keys for 'name', 'path', and 'base'.
  #
  def get_images
    request = Packet.create_request('stdapi_sys_process_image_get_images')
    images  = []

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)

    response = process.client.send_request(request)

    response.each(TLV_TYPE_IMAGE_GROUP) { |i|
      images <<
        {
          'name' => i.get_tlv_value(TLV_TYPE_IMAGE_NAME),
          'base' => i.get_tlv_value(TLV_TYPE_IMAGE_BASE),
          'path' => i.get_tlv_value(TLV_TYPE_IMAGE_FILE_PATH)
        }
    }

    return images
  end

protected
  attr_accessor :process # :nodoc:

end

end; end; end; end; end; end; end
