#!/usr/bin/perl -w

use strict;

use Test::Simple tests => 9;
use lib '..';
use Commons;


#
# test validateData
#
my %DATA = (
	'' => 0,
	'blafasdf' => 0,
	'http://fasfs.pl/' => 0,
	'fasdf../../../../' => 0.8,
	'foo bar baz/bin/sh' => 1,
	'foo bar bah/bin/zshfafa' => 1,
	'foo %s bar %s baz' => 0.8,
	'foo %n bar' => 1,

);
foreach my $data (keys %DATA) {
	ok(Commons::validateData($data) == $DATA{$data}, 'Commons::validateData');
}


#
# test sendDataToSocket
#
#
package trapper;
sub TIEHANDLE {
	my $class = shift;
	my $val;
	bless \$val, $class;
}
sub PRINT {
	my ($self, @data) = @_;
	$$self .= join('', @data);
}
sub READLINE {
	my $self = $_[0];
	return $$self;
	$$self = undef;
}
package main;
tie *SOCK, 'trapper';
%DATA = (
	'addService 127.0.0.1 tcp 5050 services/script -a' =>
		"\x00\x00" .
		"\x00\x47\x04\x06\x04\x31\x32\x33\x34\x04\x04\x04\x08\x02\x06\x00" .
		"\x00\x00\x0a\x0a\x61\x64\x64\x53\x65\x72\x76\x69\x63\x65\x0a\x09" .
		"\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x0a\x03\x74\x63\x70\x0a\x04" .
		"\x35\x30\x35\x30\x0a\x0f\x73\x65\x72\x76\x69\x63\x65\x73\x2f\x73" .
		"\x63\x72\x69\x70\x74\x0a\x02\x2d\x61"
);
foreach my $data (keys %DATA) {
	Commons::sendDataToSocket(*SOCK, [split(/ /,$data)]);
	my $a = join('', <SOCK>);
	my $result =  ($a eq $DATA{$data});
	ok($result, 'Commons::sendDataToSocket');
}


exit 0;

# vim: set ft=perl:

