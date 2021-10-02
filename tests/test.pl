#!/usr/bin/perl -w

use strict;

BEGIN {
	if (!$ENV{'LOG4PERLCONF'}) {
		$ENV{'LOG4PERLCONF'} = '../log4perl.conf';
	}
}

use Test::Harness;

my @TEST_FILES = qw(
	NodeTest.t
	commons.t
);

$Test::Harness::verbose = 1
	if $ARGV[0] && $ARGV[0] eq '-v';

runtests(@TEST_FILES);

