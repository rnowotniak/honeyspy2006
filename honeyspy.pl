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

use Log::Log4perl (':easy');
use Getopt::Long;
use POSIX ('setsid');
use Master;
use Node;

#Log::Log4perl->easy_init($DEBUG);

sub usage {
	my $exitcode = @_;
	print "\n";
	print "HoneySpy -- advance honeypot environment\n";
	print "Copyright (C) 2005 Robert Nowotniak\n";
	print "Copyright (C) 2005 Michal Wysokinski\n";
	print "\n";
	print "This program is free software; you can redistribute it and/or\n";
	print "modify it under the terms of the GNU General Public License\n";
	print "as published by the Free Software Foundation; either version 2\n";
	print "of the License, or (at your option) any later version.\n";
	print "\n";

	print "Usage:\n";
	print "   $0 <OPTIONS>\n\n";
	print "   Options are:\n";
	print "       -c|--config <config_file>\n";
	print "      [-f|--foreground]\n";
	print "      [-h|--help]\n";
	print "      [-m|--master]\n\n";
	exit $exitcode;
}

Log::Log4perl::init($ENV{'LOG4PERLCONF'});


my($master_mode, $config, $help, $foreground);

if (!GetOptions(
	'master|m'   => \$master_mode,
	'help|h'     => \$help,
	'config|c=s' => \$config,
	'foreground|f' => \$foreground,
)) {
	usage(1); 
}

if (!defined $config) {
	usage(1);
}

if ($help) {
	usage(0);
}

my $node = $master_mode ?
	Master->new($config) : Node->new($config);

if (!$foreground) {
	fork and exit 0;
	fork and exit 0;
	setsid();
	close STDIN;
	close STDOUT;
	close STDERR;
	open STDIN, '</dev/null';
	open STDOUT, '>/dev/null';
	open STDERR, '>/dev/null';
}

$node->run();

exit 0;

=head1 NAME

honeyspy - advaned honeypot environment

=head1 SYNOPSIS

honeyspy [-h|--help] [-f|--foreground] [-m|--master] -c|--config <config_file>

=head1 DESCRIPTION

HoneySpy is a collection of tools and scripts, which allows you to create,
setup, maintain and monitor the network of honeypot servers. It's written in
general in Perl.

By using tools such as p0f, ebtables, ippersonality and others on network nodes
it allows you to simulate various operating system's TCP/IP stack, and
detecting it on the remote hosts at the same time.

Mangling MAC addresses of used IP aliases is possible as well (to prevent
detection of honeypots by the attackers, who compared MAC addresses in the
network).

=head1 OPTIONS

=over

=item -c, --config <config_file>

config file

=item -f, --foreground

run in foreground. helpful for debugging.

=item -h, --help

show help

=item -m, --master

master node mode

=back

=head1 FILES

=head2 CONFIGURATION FILE

Node configuration file is simple Perl script,
which is included during node startup by

 do <config_file>,

as recommended in Tom Christiansen FMTEYEWTK.

It should contain lexical scoped (my) $config reference
to hash with following keys:

=over

=item name

Node's name

=item ca_file

Network CA's certificate filename

=item ssl_key

Node's private key filename

=item ssl_cert

Node's certificate filename

=item listen_addr
(Master node only)

IP address to listen for sensors

=item listen_port
(Master node only)

Port number for listening

=item master_addr
(Slave node only)

Address of Master node

=item master_port
(Slave node only)

Port number on Master node

=back


=head2 CONFIGURATION FILE EXAMPLES

=head3 Master node config file

 my $config = {
	 'name'         => 'master',
	 'listen_addr'  => '0.0.0.0',
	 'listen_port'  => '9000',
	 'ca_file'      => 'certs/master-cert.pem',
	 'ssl_key'      => 'certs/master-key.pem',
	 'ssl_cert'     => 'certs/master-cert.pem',
 };

=head3 Slave node config file

 my $config = {
 	'name'         => 'master',
 	'master_addr'	=> '192.168.1.1',
 	'master_port'	=> '9000',
 	'ca_file'      => 'certs/master-cert.pem',
 	'ssl_key'      => 'certs/master-key.pem',
 	'ssl_cert'     => 'certs/master-cert.pem',
 };

=head1 BUGS

A lot of, probably.

=head1 AUTHORS

This software is written by Robert Nowotniak and Michal Wysokinski.

=head1 COPYRIGHT

 Copyright (C) 2005   Robert Nowotniak <robert at nowotniak.com>
 Copyright (C) 2005   Michal Wysokinski <wolk at o2.pl>

This is free software; see the source for copying conditions.
There is NO waranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


=head1 SEE ALSO

arptables(8), ebtables(8), tcpdump(8), p0f(1), inetd(8),
Log::Log4perl(3pm), Log::Log4perl::Config(3pm), Log::Log4perl::Appender(3pm)

=cut

