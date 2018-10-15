##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::SMB::Client::PipeAuditor

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

        If the machine is missing the MS17-010 patch, the module will check for an
        existing DoublePulsar (ring 0 shellcode/malware) infection.

        This module does not require valid SMB credentials in default server
        configurations. It can log on as the user "\" and connect to IPC$.
      },
      'Author'         =>
          [
            'Sean Dillon <sean.dillon@risksense.com>', # @zerosum0x0
            'Luke Jennings' # DoublePulsar detection Python code
          ],
      'References'     =>
        [
          [ 'CVE', '2017-0143'],
          [ 'CVE', '2017-0144'],
          [ 'CVE', '2017-0145'],
          [ 'CVE', '2017-0146'],
          [ 'CVE', '2017-0147'],
          [ 'CVE', '2017-0148'],
          [ 'MSB', 'MS17-010'],
          [ 'URL', 'https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html'],
          [ 'URL', 'https://github.com/countercept/doublepulsar-detection-script'],
          [ 'URL', 'https://technet.microsoft.com/en-us/library/security/ms17-010.aspx']
        ],
      'License'        => MSF_LICENSE,
      'Notes' =>
          {
              'AKA' => [
                  'DOUBLEPULSAR',
                  'ETERNALBLUE'
              ]
          }
    ))

    register_options(
      [
        OptBool.new('CHECK_DOPU', [false, 'Check for DOUBLEPULSAR on vulnerable hosts', true]),
        OptBool.new('CHECK_ARCH', [false, 'Check for architecture on vulnerable hosts', true]),
        OptBool.new('CHECK_PIPE', [false, 'Check for named pipe on vulnerable hosts', false])
      ])
  end

  # algorithm to calculate the XOR Key for DoublePulsar knocks
  def calculate_doublepulsar_xor_key(s)
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x & 0xffffffff  # this line was added just to truncate to 32 bits
  end

  # The arch is adjacent to the XOR key in the SMB signature
  def calculate_doublepulsar_arch(s)
    s == 0 ? 'x86 (32-bit)' : 'x64 (64-bit)'
  end

  def run_host(ip)
    begin
      ipc_share = "\\\\#{ip}\\IPC$"

      tree_id = do_smb_setup_tree(ipc_share)
      vprint_status("Connected to #{ipc_share} with TID = #{tree_id}")

      status = do_smb_ms17_010_probe(tree_id)
      vprint_status("Received #{status} with FID = 0")

      if status == "STATUS_INSUFF_SERVER_RESOURCES"
        os = simple.client.peer_native_os

        if datastore['CHECK_ARCH']
          case dcerpc_getarch
          when ARCH_X86
            os << ' x86 (32-bit)'
          when ARCH_X64
            os << ' x64 (64-bit)'
          end
        end

        print_good("Host is likely VULNERABLE to MS17-010! - #{os}")
        report_vuln(
          host: ip,
          name: self.name,
          refs: self.references,
          info: "STATUS_INSUFF_SERVER_RESOURCES for FID 0 against IPC$ - #{os}"
        )

        # vulnerable to MS17-010, check for DoublePulsar infection
        if datastore['CHECK_DOPU']
          code, signature1, signature2 = do_smb_doublepulsar_probe(tree_id)

          if code == 0x51
            xor_key = calculate_doublepulsar_xor_key(signature1).to_s(16).upcase
            arch = calculate_doublepulsar_arch(signature2)
            print_warning("Host is likely INFECTED with DoublePulsar! - Arch: #{arch}, XOR Key: 0x#{xor_key}")
            report_vuln(
              host: ip,
              name: "MS17-010 DoublePulsar Infection",
              refs: self.references,
              info: "MultiPlexID += 0x10 on Trans2 request - Arch: #{arch}, XOR Key: 0x#{xor_key}"
            )
          end
        end

        if datastore['CHECK_PIPE']
          pipe_name, _ = check_named_pipes(return_first: true)

          return unless pipe_name

          print_good("Named pipe found: #{pipe_name}")

          report_note(
            host:  ip,
            port:  rport,
            proto: 'tcp',
            sname: 'smb',
            type:  'MS17-010 Named Pipe',
            data:  pipe_name
          )
        end
      elsif status == "STATUS_ACCESS_DENIED" or status == "STATUS_INVALID_HANDLE"
        # STATUS_ACCESS_DENIED (Windows 10) and STATUS_INVALID_HANDLE (others)
        print_error("Host does NOT appear vulnerable.")
      else
        print_error("Unable to properly detect if host is vulnerable.")
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

  def do_smb_setup_tree(ipc_share)
    connect

    # logon as user \
    simple.login(datastore['SMBName'], datastore['SMBUser'], datastore['SMBPass'], datastore['SMBDomain'])

    # connect to IPC$
    simple.connect(ipc_share)

    # return tree
    return simple.shares[ipc_share]
  end

  def do_smb_doublepulsar_probe(tree_id)
    # make doublepulsar knock
    pkt = make_smb_trans2_doublepulsar(tree_id)

    sock.put(pkt)
    bytes = sock.get_once

    # convert packet to response struct
    pkt = Rex::Proto::SMB::Constants::SMB_TRANS_RES_HDR_PKT.make_struct
    pkt.from_s(bytes[4..-1])

    return pkt['SMB'].v['MultiplexID'], pkt['SMB'].v['Signature1'], pkt['SMB'].v['Signature2']
  end

  def do_smb_ms17_010_probe(tree_id)
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

    return smberr.get_error(code)
  end

  def make_smb_trans2_doublepulsar(tree_id)
    # make a raw transaction packet
    # this one is a trans2 packet, the checker is trans
    pkt = Rex::Proto::SMB::Constants::SMB_TRANS2_PKT.make_struct
    simple.client.smb_defaults(pkt['Payload']['SMB'])

    # opcode 0x0e = SESSION_SETUP
    setup = "\x0e\x00\x00\x00"
    setup_count = 1             # 1 word
    trans = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # calculate offsets to the SetupData payload
    base_offset = pkt.to_s.length + (setup.length) - 4
    param_offset = base_offset + trans.length
    data_offset = param_offset # + 0

    # packet baselines
    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['MultiplexID'] = 65
    pkt['Payload']['SMB'].v['Flags2'] = 0xc007
    pkt['Payload']['SMB'].v['TreeID'] = tree_id
    pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count
    pkt['Payload'].v['Timeout'] = 0x00a4d9a6
    pkt['Payload'].v['ParamCountTotal'] = 12
    pkt['Payload'].v['ParamCount'] = 12
    pkt['Payload'].v['ParamCountMax'] = 1
    pkt['Payload'].v['DataCountMax'] = 0
    pkt['Payload'].v['ParamOffset'] = 66
    pkt['Payload'].v['DataOffset'] = 78

    pkt['Payload'].v['SetupCount'] = setup_count
    pkt['Payload'].v['SetupData'] = setup
    pkt['Payload'].v['Payload'] = trans

    pkt.to_s
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
