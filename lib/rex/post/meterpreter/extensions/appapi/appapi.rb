# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/appapi/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module AppApi

###
#
# Application interface to control Applications on the device
#
###
class AppApi < Extension

  #
  # Typical extension initialization routine.
  #
  # @param client (see Extension#initialize)
  def initialize(client)
    super(client, 'appapi')

    client.register_extension_aliases(
      [
        {
          'name' => 'appapi',
          'ext'  => self
        }
      ])
  end

  #
  # Get list of installed applications
  #
  def app_list(app_opt)
    request = Packet.create_request('appapi_app_list')
    request.add_tlv(TLV_TYPE_APPS_LIST_OPT, app_opt)
    response = client.send_request(request)
    names = []
    response.get_tlvs(TLV_TYPE_APPS_LIST).each do |tlv|
      names << tlv.value
    end
    names
  end

  #
  # Uninstall application
  #
  def app_uninstall(packagename)

    request = Packet.create_request('appapi_app_uninstall')
    request.add_tlv(TLV_TYPE_APP_PACKAGE_NAME, packagename)
    response = client.send_request(request)

    response.get_tlv(TLV_TYPE_APP_ENUM).value
  end

  #
  # Install application
  #
  def app_install(apk_path)
    request = Packet.create_request('appapi_app_install')
    request.add_tlv(TLV_TYPE_APP_APK_PATH, apk_path)
    response = client.send_request(request)

    response.get_tlv(TLV_TYPE_APP_ENUM).value
  end

  #
  # Start Main Activity for installed application by Package name
  #
  def app_run(packagename)
    request = Packet.create_request('appapi_app_run')
    request.add_tlv(TLV_TYPE_APP_PACKAGE_NAME, packagename)
    response = client.send_request(request)
    response.get_tlv(TLV_TYPE_APP_RUN_ENUM).value
  end

end

end; end; end; end; end

