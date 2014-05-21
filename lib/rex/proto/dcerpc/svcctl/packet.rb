# -*- coding: binary -*-
module Rex

###
# This module implements MSRPC functions that control creating, deleting,
# starting, stopping, and querying system services.
###
module Proto::DCERPC::SVCCTL

  require 'rex/constants/windows'
  NDR = Rex::Encoder::NDR


class Client

  include Rex::Constants::Windows

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
  # @param access [Fixnum] the access flags requested.
  #
  # @return [String, Integer] the handle to the service control manager or nil if
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
      print_error("#{peer} - Error getting scm handle: #{e}")
    end

    return scm_handle, scm_status
  end

  # Calls CreateServiceW() to create a system service.  Returns a handle to
  # the service on success, or nil.
  #
  # @param scm_handle [String] the SCM handle (from dce_openscmanagerw()).
  # @param service_name [String] the service name.
  # @param display_name [String] the display name.
  # @param binary_path [String] the path of the binary to run.
  # @param opts [Hash] a hash containing the following keys and values:
  #                 access [Fixnum] the access level (default is maximum).
  #                 type [Fixnum] the type of service (default is interactive,
  #                               own process).
  #                 start [Fixnum] the start options (default is on demand).
  #                 errors [Fixnum] the error options (default is ignore).
  #                 load_order_group [Fixnum] the load order group.
  #                 dependencies [Fixnum] the dependencies of the service.
  #                 service_start [Fixnum]
  #                 password1 [Fixnum]
  #                 password2 [Fixnum]
  #                 password3 [Fixnum]
  #                 password4 [Fixnum]
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
      if response
        svc_status = error_code(response[24,4])

        if svc_status == ERROR_SUCCESS
          svc_handle = response[4,20]
        end
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      print_error("#{peer} - Error creating service: #{e}")
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
      print_error("#{peer} - Error changing service description : #{e}")
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
        svc_status = error_code(response[20,4])
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      print_error("#{peer} - Error closing service handle: #{e}")
    end

    svc_status
  end

  # Calls OpenServiceW to obtain a handle to an existing service.
  #
  # @param scm_handle [String] the SCM handle (from dce_openscmanagerw()).
  # @param service_name [String] the name of the service to open.
  # @param access [Fixnum] the level of access requested (default is maximum).
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
      print_error("#{peer} - Error opening service handle: #{e}")
    end

    svc_handle
  end

  # Calls StartService() on a handle to an existing service in order to start
  # it.  Returns true on success, or false.
  #
  # @param svc_handle [String] the handle of the service to start (from
  #                            dce_openservicew()).
  # @param magic1 [Fixnum] an unknown value.
  # @param magic2 [Fixnum] another unknown value.
  #
  # @return [Integer] Windows error code
  def startservice(svc_handle, magic1 = 0, magic2 = 0)
    svc_status = nil
    stubdata = svc_handle + NDR.long(magic1) + NDR.long(magic2)

    begin
      response = dcerpc_client.call(0x13, stubdata)
      if response
        svc_status = error_code(response)
      end
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      print_error("#{peer} - Error starting service: #{e}")
    end

    svc_status
  end

  # Stops a running service.
  #
  # @param svc_handle [String] the handle of the service to stop (from
  #                            dce_openservicew()).
  #
  # @return [Integer] Windows error code
  def stopservice(svc_handle)
    dce_controlservice(svc_handle, SERVICE_CONTROL_STOP)
  end

  # Controls an existing service.
  #
  # @param svc_handle [String] the handle of the service to control
  #                            (from dce_openservicew()).
  # @param operation [Fixnum] the operation number to perform (1 = stop
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
      print_error("#{peer} - Error controlling service: #{e}")
    end

    svc_status
  end

  # Calls DeleteService() to delete a service.
  #
  # @param svc_handle [String] the handle of the service to delete (from
  #                            dce_openservicew()).
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
      print_error("#{peer} - Error deleting service: #{e}")
    end

    svc_status
  end

  # Calls QueryServiceStatus() to query the status of a service.
  #
  # @param svc_handle [String] the handle of the service to query (from
  #                            dce_openservicew()).
  #
  # @return [Fixnum] Returns 0 if the query failed (i.e.: a state was returned
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
      print_error("#{peer} - Error deleting service: #{e}")
    end

    ret
  end

end
end
end

