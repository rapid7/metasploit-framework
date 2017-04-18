##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS17-010 SMB RCE Detection',
      'Description'    => %q{
        Uses information disclosure to determine if MS17-010 has been patched or not.
        Specifically, it connects to the IPC$ tree and attempts a transaction on FID 0.
        If the status returned is "STATUS_INSUFF_SERVER_RESOURCES", the machine does
        not have the MS17-010 patch.

        This module does not require valid SMB credentials in default server
        configurations. It can log on as the user "\" and connect to IPC$.
      },
      'Author'         => [ 'Sean Dillon <sean.dillon@risksense.com>' ],
      'References'     =>
        [
          [ 'CVE', '2017-0143'],
          [ 'CVE', '2017-0144'],
          [ 'CVE', '2017-0145'],
          [ 'CVE', '2017-0146'],
          [ 'CVE', '2017-0147'],
          [ 'CVE', '2017-0148'],
          [ 'MSB', 'MS17-010'],
          [ 'URL', 'https://technet.microsoft.com/en-us/library/security/ms17-010.aspx']
        ],
      'License'        => MSF_LICENSE
    ))
  end

  def run_host(ip)
    begin
      status = do_smb_probe(ip)

      if status == "STATUS_INSUFF_SERVER_RESOURCES"
        print_warning("Host is likely VULNERABLE to MS17-010!")
        report_vuln(
          host: ip,
          name: self.name,
          refs: self.references,
          info: 'STATUS_INSUFF_SERVER_RESOURCES for FID 0 against IPC$'
        )
      elsif status == "STATUS_ACCESS_DENIED" or status == "STATUS_INVALID_HANDLE"
        # STATUS_ACCESS_DENIED (Windows 10) and STATUS_INVALID_HANDLE (others)
        print_good("Host does NOT appear vulnerable.")
      else
        print_bad("Unable to properly detect if host is vulnerable.")
      end

    rescue ::Interrupt
      print_status("Exiting on interrupt.")
      raise $!
    rescue ::Rex::Proto::SMB::Exceptions::LoginError
      print_error("An SMB Login Error occurred while connecting to the IPC$ tree.")
    rescue ::Exception => e
      vprint_error("#{e.class}: #{e.message}")
    ensure
      disconnect
    end
  end

  def do_smb_probe(ip)
    connect

    # logon as user \
    simple.login(datastore['SMBName'], datastore['SMBUser'], datastore['SMBPass'], datastore['SMBDomain'])

    # connect to IPC$
    ipc_share = "\\\\#{ip}\\IPC$"
    simple.connect(ipc_share)
    tree_id = simple.shares[ipc_share]

    print_status("Connected to #{ipc_share} with TID = #{tree_id}")

    # request transaction with fid = 0
    pkt = make_smb_trans_ms17_010(tree_id)
    sock.put(pkt)
    bytes = sock.get_once

    # convert packet to response struct
    pkt = Rex::Proto::SMB::Constants::SMB_TRANS_RES_HDR_PKT.make_struct
    pkt.from_s(bytes[4..-1])

    # convert error code to string
    code = pkt['SMB'].v['ErrorClass']
    smberr = Rex::Proto::SMB::Exceptions::ErrorCode.new
    status = smberr.get_error(code)

    print_status("Received #{status} with FID = 0")
    status
  end

  def make_smb_trans_ms17_010(tree_id)
    # make a raw transaction packet
    pkt = Rex::Proto::SMB::Constants::SMB_TRANS_PKT.make_struct
    simple.client.smb_defaults(pkt['Payload']['SMB'])

    # opcode 0x23 = PeekNamedPipe, fid = 0
    setup = "\x23\x00\x00\x00"
    setup_count = 2             # 2 words
    trans = "\\PIPE\\\x00"

    # calculate offsets to the SetupData payload
    base_offset = pkt.to_s.length + (setup.length) - 4
    param_offset = base_offset + trans.length
    data_offset = param_offset # + 0

    # packet baselines
    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_TRANSACTION
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0x2801 # 0xc803 would unicode
    pkt['Payload']['SMB'].v['TreeID'] = tree_id
    pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count
    pkt['Payload'].v['ParamCountMax'] = 0xffff
    pkt['Payload'].v['DataCountMax'] = 0xffff
    pkt['Payload'].v['ParamOffset'] = param_offset
    pkt['Payload'].v['DataOffset'] = data_offset

    # actual magic: PeekNamedPipe FID=0, \PIPE\
    pkt['Payload'].v['SetupCount'] = setup_count
    pkt['Payload'].v['SetupData'] = setup
    pkt['Payload'].v['Payload'] = trans

    pkt.to_s
  end
end
