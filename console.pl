#!/usr/bin/perl -w
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


use strict;

BEGIN {
	if (!$ENV{'LOG4PERLCONF'}) {
		$ENV{'LOG4PERLCONF'} = 'log4perl.conf';
	}
}

use Sensor;
use IO::Socket::SSL;
use Term::ReadLine;
use Log::Log4perl (':easy');
Log::Log4perl->easy_init($WARN);

use constant HISTORY_FILE => "$ENV{HOME}/.honeyspy_history";
use constant COMPLETION_LIST => [qw/
	getName
	getAbilities
	runOnNode
	getSensors
	kill

	addService
	delService
	getService
	getServicesLimit
	setServicesLimit

	addIPAlias
	delIPAlias
	getIPAlias

	getAvailableFingerprints
	setFingerprint
	delFingerprint

	setMAC
	getMAC
	delMAC

	enableP0f
	disableP0f
	setP0fOption

	enablePcap
	addFilter
	replaceFilters
	delFilter
	getFilter
/];


if ($#ARGV != 1) {
	print "Usage:\n\t$0 <host> <port>\n";
	exit 1;
}

my $logger = get_logger();

my $master = IO::Socket::SSL->new( PeerAddr => $ARGV[0],
	PeerPort => $ARGV[1],
	Proto    => 'tcp',
	SSL_use_cert => 1,

	SSL_key_file => 'certs/admin-key.enc',
	SSL_cert_file => 'certs/admin-cert.pem',
	SSL_ca_file => 'certs/master-cert.pem',

	SSL_verify_mode => 0x01);

if (!$master) { 
	$logger->fatal("unable to create socket: ", IO::Socket::SSL->errstr, "\n");
	exit 1;
}

print <<EOF;
************************************************************
***            HoneySpy experimental console             ***
************************************************************
EOF

print "\nConnection established\n";

my $prompt = '> ';
my $term = new Term::ReadLine 'HoneySpy console';
my $rl_attribs = $term->Attribs;
$rl_attribs->{'completion_entry_function'} = 
	$rl_attribs->{'list_completion_function'};
$rl_attribs->{'completion_word'} = COMPLETION_LIST;
$term->read_history(HISTORY_FILE)
 if -r HISTORY_FILE;


my $s = new Sensor({
	name => 'main',
	socket => $master,
});


print $prompt;
while (defined($_ = $term->readline($prompt))) {
	$term->addhistory($_) if /\S/;
	next unless ($_);

	my ($cmd, @args) = split(/\s+/);

	$s->doOnReturn(sub {
			my ($self, @res) = @_;
			local $" = "\n   -> ";
			print "@res\n" if @res && $res[0];
		});
	$s->call($cmd, 1, @args);
	$s->read('return_code');

	print $prompt;
}

system("touch " . HISTORY_FILE);
$term->append_history(100, HISTORY_FILE);

