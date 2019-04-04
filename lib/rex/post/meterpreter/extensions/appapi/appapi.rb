# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/appapi/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module AppApi

###
#
# Application interface to controle Application in Device
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
  # Get lits of android device installed applications
  #
  def app_list(app_opt)
    request = Packet.create_request('appapi_app_list')
    request.add_tlv(TLV_TYPE_APPS_LIST_OPT, app_opt)
    response = client.send_request(request)
    names = []
    response.get_tlvs(TLV_TYPE_APPS_LIST).each do |tlv|
      names << tlv.value
    end
    names # => Return
  end

  #
  # unistall application (user mode => ask the use to uninstall)
  #
  def app_uninstall(packname, use_root)
    request = Packet.create_request('appapi_app_uninstall')
    request.add_tlv(TLV_TYPE_APP_PACKAGE_NAME, packname)
    request.add_tlv(TLV_TYPE_APP_USEROOT, use_root)
    response = client.send_request(request)

    response.get_tlv(TLV_TYPE_APP_ENUM).value # => Return
  end

  #
  # install application (user mode => ask the use to install)
  #
  def app_install(apk_path, use_root)
    request = Packet.create_request('appapi_app_install')
    request.add_tlv(TLV_TYPE_APP_APK_PATH, apk_path)
    request.add_tlv(TLV_TYPE_APP_USEROOT, use_root)
    response = client.send_request(request)

    response.get_tlv(TLV_TYPE_APP_ENUM).value # => Return
  end

  #
  # Start Main Activty for installed application by Package name
  #
  def app_run(packname)
    request = Packet.create_request('appapi_app_run')
    request.add_tlv(TLV_TYPE_APP_PACKAGE_NAME, packname)
    response = client.send_request(request)
    response.get_tlv(TLV_TYPE_APP_RUN_ENUM).value # => Return
  end

end

end; end; end; end; end

