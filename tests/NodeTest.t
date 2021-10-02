#!/usr/bin/perl -w

use strict;

use Test::Simple tests => 12;

use lib '..';
use Node;

my $node = Node->new();

ok(ref $node eq 'Node', 'Node');

ok(! $node->{'r_set'}->handles);
ok(! $node->{'w_set'}->handles);
ok(! $node->{'e_set'}->handles);

$node->_addfh(4, 'r');
$node->_addfh(5, 'w');
$node->_addfh(6);

ok($node->{'r_set'}->count() == 2
	&& $node->{'r_set'}->exists(4)
	&& $node->{'r_set'}->exists(6)
);
ok($node->{'w_set'}->count() == 2
	&& $node->{'w_set'}->exists(5)
	&& $node->{'w_set'}->exists(6)
);
ok($node->{'e_set'}->count() == 1
	&& $node->{'e_set'}->exists(6)
);

$node->_removefh(4, 'r');
$node->_removefh(5, 'w');
$node->_removefh(6);

ok(! $node->{'r_set'}->count);
ok(! $node->{'w_set'}->count);
ok(! $node->{'e_set'}->count);


# pcap
$node->delFilter();
ok(!@{$node->{'pcap_filters'}});

my $f1 = 'icmp and dst host 127.0.0.1';
my $f2 = 'udp and port 53 and host 0.0.0.0';
$node->addFilter($f1);
$node->addFilter($f2);

ok("@{[$node->getFilters()]}" eq "$f1 $f2");

exit 0;

# vim: set ft=perl:

