# -*- coding: binary -*-

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# This class provides access to remote system configuration and information.
#
###
class Config

  SYSTEM_SID = 'S-1-5-18'

  def initialize(client)
    self.client = client
  end

  #
  # Returns the username that the remote side is running as.
  #
  def getuid(refresh: true)
    if @uid.nil? || refresh
      request  = Packet.create_request('stdapi_sys_config_getuid')
      response = client.send_request(request)
      @uid = client.unicode_filter_encode( response.get_tlv_value(TLV_TYPE_USER_NAME) )
    end
    @uid
  end

  #
  # Gets the SID of the current process/thread.
  #
  def getsid
    request = Packet.create_request('stdapi_sys_config_getsid')
    response = client.send_request(request)
    response.get_tlv_value(TLV_TYPE_SID)
  end

  #
  # Determine if the current process/thread is running as SYSTEM
  #
  def is_system?
    getsid == SYSTEM_SID
  end

  #
  # Returns a list of currently active drivers used by the target system
  #
  def getdrivers
    request = Packet.create_request('stdapi_sys_config_driver_list')
    response = client.send_request(request)

    result = []

    response.each(TLV_TYPE_DRIVER_ENTRY) do |driver|
      result << {
        basename: driver.get_tlv_value(TLV_TYPE_DRIVER_BASENAME),
        filename: driver.get_tlv_value(TLV_TYPE_DRIVER_FILENAME)
      }
    end

    result
  end

  #
  # Returns a hash of requested environment variables, along with their values.
  # If a requested value doesn't exist in the response, then the value wasn't found.
  #
  def getenvs(*var_names)
    request = Packet.create_request('stdapi_sys_config_getenv')

    var_names.each do |v|
      request.add_tlv(TLV_TYPE_ENV_VARIABLE, v)
    end

    response = client.send_request(request)
    result = {}

    response.each(TLV_TYPE_ENV_GROUP) do |env|
      var_name = env.get_tlv_value(TLV_TYPE_ENV_VARIABLE)
      var_value = env.get_tlv_value(TLV_TYPE_ENV_VALUE)
      result[var_name] = var_value
    end

    result
  end

  #
  # Returns the value of a single requested environment variable name
  #
  def getenv(var_name)
    _, value = getenvs(var_name).first
    value
  end

  #
  # Returns the target's local system date and time.
  #
  def localtime
    request = Packet.create_request('stdapi_sys_config_localtime')
    response = client.send_request(request)
    (response.get_tlv_value(TLV_TYPE_LOCAL_DATETIME) || "").strip
  end

  #
  # Returns a hash of information about the remote computer.
  #
  def sysinfo(refresh: false)
    request  = Packet.create_request('stdapi_sys_config_sysinfo')
    if @sysinfo.nil? || refresh
      response = client.send_request(request)

      @sysinfo = {
        'Computer'        => response.get_tlv_value(TLV_TYPE_COMPUTER_NAME),
        'OS'              => response.get_tlv_value(TLV_TYPE_OS_NAME),
        'Architecture'    => response.get_tlv_value(TLV_TYPE_ARCHITECTURE),
        'BuildTuple'      => response.get_tlv_value(TLV_TYPE_BUILD_TUPLE),
        'System Language' => response.get_tlv_value(TLV_TYPE_LANG_SYSTEM),
        'Domain'          => response.get_tlv_value(TLV_TYPE_DOMAIN),
        'Logged On Users' => response.get_tlv_value(TLV_TYPE_LOGGED_ON_USER_COUNT)
      }

      # make sure we map the architecture across to x64 if x86_64 is returned
      # to keep arch consistent across all session/machine types
      if @sysinfo['Architecture']
        @sysinfo['Architecture'] = ARCH_X64 if @sysinfo['Architecture'].strip == ARCH_X86_64
      end
    end
    @sysinfo
  end

  #
  # Calls RevertToSelf on the remote machine.
  #
  def revert_to_self
    client.send_request(Packet.create_request('stdapi_sys_config_rev2self'))
  end

  #
  # Steals the primary token from a target process
  #
  def steal_token(pid)
    req = Packet.create_request('stdapi_sys_config_steal_token')
    req.add_tlv(TLV_TYPE_PID, pid.to_i)
    res = client.send_request(req)
    client.unicode_filter_encode( res.get_tlv_value(TLV_TYPE_USER_NAME) )
  end

  #
  # Drops any assumed token
  #
  def drop_token
    req = Packet.create_request('stdapi_sys_config_drop_token')
    res = client.send_request(req)
    client.unicode_filter_encode( res.get_tlv_value(TLV_TYPE_USER_NAME) )
  end

  #
  # Enables all possible privileges
  #
  def getprivs
    req = Packet.create_request('stdapi_sys_config_getprivs')
    ret = []
    res = client.send_request(req)
    res.each(TLV_TYPE_PRIVILEGE) do |p|
      ret << p.value
    end
    ret
  end

protected

  attr_accessor :client

end

end; end; end; end; end; end

