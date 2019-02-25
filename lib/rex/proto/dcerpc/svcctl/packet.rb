# -*- coding: binary -*-
module Rex

###
# This module implements MSRPC functions that control creating, deleting,
# starting, stopping, and querying system services.
###
module Proto::DCERPC::SVCCTL

  require 'windows_error'
  require 'windows_error/win32'
  require 'msf/core/exploit/windows_constants'
  NDR = Rex::Encoder::NDR


class Client

  include WindowsError::Win32
  include Msf::Exploit::Windows_Constants

  attr_accessor :dcerpc_client

  def initialize(dcerpc_client)
    self.dcerpc_client = dcerpc_client
  end

  # Returns the Windows Error Code in numeric format
  #
  # @param raw_error [String] the raw error code in binary format.
  #
  # @return [Integer] the Windows Error Code integer.
  def error_code(raw_error)
    raw_error.unpack('V').first
  end

  # Calls OpenSCManagerW() to obtain a handle to the service control manager.
  #
  # @param rhost [String] the target host.
  # @param access [Integer] the access flags requested.
  #
  # @return [Array<String,Integer>] the handle to the service control manager or nil if
  #   the call is not successful and the Windows error code
  def openscmanagerw(rhost, access = SC_MANAGER_ALL_ACCESS)
    scm_handle = nil
    scm_status = nil
    stubdata =
      NDR.uwstring("\\\\#{rhost}") +
      NDR.long(0) +
      NDR.long(access)
    begin
      response = dcerpc_client.call(OPEN_SC_MANAGER_W, stubdata)
      if response
        scm_status = error_code(response[20,4])
        if scm_status == ERROR_SUCCESS
          scm_handle = response[0,20]
        end
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error getting scm handle: #{e}")
    end

    [scm_handle, scm_status]
  end

  # Calls CreateServiceW() to create a system service.  Returns a handle to
  # the service on success, or nil.
  #
  # @param scm_handle [String] the SCM handle (from {#openscmanagerw}).
  # @param service_name [String] the service name.
  # @param display_name [String] the display name.
  # @param binary_path [String] the path of the binary to run.
  # @param opts [Hash] arguments for CreateServiceW()
  # @option opts [Integer] :access (SERVICE_ALL_ACCESS) the access level.
  # @option opts [Integer] :type (SERVICE_WIN32_OWN_PROCESS ||
  #   SERVICE_INTERACTIVE_PROCESS) the type of service.
  # @option opts [Integer] :start (SERVICE_DEMAND_START) the start options.
  # @option opts [Integer] :errors (SERVICE_ERROR_IGNORE) the error options.
  # @option opts [Integer] :load_order_group (0) the load order group.
  # @option opts [Integer] :dependencies (0) the dependencies of the service.
  # @option opts [Integer] :service_start (0)
  # @option opts [Integer] :password1 (0)
  # @option opts [Integer] :password2 (0)
  # @option opts [Integer] :password3 (0)
  # @option opts [Integer] :password4 (0)
  #
  # @return [String, Integer] a handle to the created service, windows
  #   error code.
  def createservicew(scm_handle, service_name, display_name, binary_path, opts)
    default_opts = {
      :access => SERVICE_ALL_ACCESS,
      :type => SERVICE_WIN32_OWN_PROCESS || SERVICE_INTERACTIVE_PROCESS,
      :start => SERVICE_DEMAND_START,
      :errors => SERVICE_ERROR_IGNORE,
      :load_order_group => 0,
      :dependencies => 0,
      :service_start => 0,
      :password1 => 0,
      :password2 => 0,
      :password3 => 0,
      :password4 => 0
    }.merge(opts)

    svc_handle  = nil
    svc_status  = nil
    stubdata = scm_handle +
      NDR.wstring(service_name) +
      NDR.uwstring(display_name) +
      NDR.long(default_opts[:access]) +
      NDR.long(default_opts[:type]) +
      NDR.long(default_opts[:start]) +
      NDR.long(default_opts[:errors]) +
      NDR.wstring(binary_path) +
      NDR.long(default_opts[:load_order_group]) +
      NDR.long(default_opts[:dependencies]) +
      NDR.long(default_opts[:service_start]) +
      NDR.long(default_opts[:password1]) +
      NDR.long(default_opts[:password2]) +
      NDR.long(default_opts[:password3]) +
      NDR.long(default_opts[:password4])
    begin
      response = dcerpc_client.call(CREATE_SERVICE_W, stubdata)
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error creating service: #{e}")
    end

    if response
      svc_status = error_code(response[24,4])
      if svc_status == ERROR_SUCCESS
        svc_handle = response[4,20]
      end
    end

    return svc_handle, svc_status
  end

  # Calls ChangeServiceConfig2() to change the service description.
  #
  # @param svc_handle [String] the service handle to change.
  # @param service_description [String] the service description.
  #
  # @return [Integer] Windows error code
  def changeservicedescription(svc_handle, service_description)
    svc_status = nil
    stubdata =
      svc_handle +
      NDR.long(SERVICE_CONFIG_DESCRIPTION) +
      NDR.long(1) + # lpInfo -> *SERVICE_DESCRIPTION
      NDR.long(0x0200) + # SERVICE_DESCRIPTION struct
      NDR.long(0x04000200) +
      NDR.wstring(service_description)
    begin
      response = dcerpc_client.call(CHANGE_SERVICE_CONFIG2_W, stubdata) # ChangeServiceConfig2
      svc_status = error_code(response)
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error changing service description : #{e}")
    end

    svc_status
  end


  # Calls CloseHandle() to close a handle.
  #
  # @param handle [String] the handle to close.
  #
  # @return [Integer] Windows error code
  def closehandle(handle)
    svc_status = nil
    begin
      response = dcerpc_client.call(CLOSE_SERVICE_HANDLE, handle)
      if response
        svc_status = error_code(response)
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error closing service handle: #{e}")
    end

    svc_status
  end

  # Calls OpenServiceW to obtain a handle to an existing service.
  #
  # @param scm_handle [String] the SCM handle (from {#openscmanagerw}).
  # @param service_name [String] the name of the service to open.
  # @param access [Integer] the level of access requested (default is maximum).
  #
  # @return [String, nil] the handle of the service opened, or nil on failure.
  def openservicew(scm_handle, service_name, access = SERVICE_ALL_ACCESS)
    svc_handle = nil
    svc_status = nil
    stubdata = scm_handle + NDR.wstring(service_name) + NDR.long(access)
    begin
      response = dcerpc_client.call(OPEN_SERVICE_W, stubdata)
      if response
        svc_status = error_code(response[20,4])
        if svc_status == ERROR_SUCCESS
          svc_handle = response[0,20]
        end
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error opening service handle: #{e}")
    end

    svc_handle
  end

  # Calls StartService() on a handle to an existing service in order to start
  # it.  Returns true on success, or false.
  #
  # @param svc_handle [String] the handle of the service (from {#openservicew}).
  # @param args [Array] an array of arguments to pass to the service (or nil)
  #
  # @return [Integer] Windows error code
  def startservice(svc_handle, args=[])
    svc_status = nil

    if args.empty?
      stubdata = svc_handle + NDR.long(0) + NDR.long(0)
    else
      # This is just an arbitrary "pointer" value, gonna match it to what the real version uses
      id_value = 0x00000200

      stubdata = svc_handle
      stubdata += NDR.long(args.length) + NDR.long(id_value) + NDR.long(args.length)

      # Encode an id value for each parameter
      args.each do
        id_value += 0x04000000
        stubdata += NDR.long(id_value)
      end

      # Encode the values now
      args.each do |arg|
        # We can't use NDR.uwstring here, because we need the "id" values to come first
        stubdata += NDR.long(arg.length + 1) + NDR.long(0) + NDR.long(arg.length + 1)

        # Unicode string
        stubdata += Rex::Text.to_unicode(arg + "\0")

        # Padding
        if((arg.length % 2) == 0)
          stubdata += Rex::Text.to_unicode("\0")
        end
      end
    end

    begin
      response = dcerpc_client.call(0x13, stubdata)
      if response
        svc_status = error_code(response)
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error starting service: #{e}")
    end

    svc_status
  end

  # Stops a running service.
  #
  # @param svc_handle [String] the handle of the service (from {#openservicew}).
  #
  # @return [Integer] Windows error code
  def stopservice(svc_handle)
    dce_controlservice(svc_handle, SERVICE_CONTROL_STOP)
  end

  # Controls an existing service.
  #
  # @param svc_handle [String] the handle of the service (from {#openservicew}).
  # @param operation [Integer] the operation number to perform (1 = stop
  #                           service; others are unknown).
  #
  # @return [Integer] Windows error code
  def controlservice(svc_handle, operation)
    svc_status = nil
    begin
      response = dcerpc_client.call(CONTROL_SERVICE, svc_handle + NDR.long(operation))
      if response
       svc_status =  error_code(response[28,4])
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error controlling service: #{e}")
    end

    svc_status
  end

  # Calls DeleteService() to delete a service.
  #
  # @param svc_handle [String] the handle of the service (from {#openservicew}).
  #
  # @return [Integer] Windows error code
  def deleteservice(svc_handle)
    svc_status = nil
    begin
      response = dcerpc_client.call(DELETE_SERVICE, svc_handle)
      if response
        svc_status = error_code(response)
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error deleting service: #{e}")
    end

    svc_status
  end

  # Calls QueryServiceStatus() to query the status of a service.
  #
  # @param svc_handle [String] the handle of the service (from {#openservicew}).
  #
  # @return [Integer] Returns 0 if the query failed (i.e.: a state was returned
  #                  that isn't implemented), 1 if the service is running, and
  #                  2 if the service is stopped.
  def queryservice(svc_handle)
    ret = 0

    begin
      response = dcerpc_client.call(QUERY_SERVICE_STATUS, svc_handle)
      if response[0,9] == "\x10\x00\x00\x00\x04\x00\x00\x00\x01"
        ret = 1
      elsif response[0,9] == "\x10\x00\x00\x00\x01\x00\x00\x00\x00"
        ret = 2
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      elog("Error deleting service: #{e}")
    end

    ret
  end

end
end
end

