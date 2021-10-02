#!/usr/bin/perl -w

use strict;
use Log::Log4perl;

package subsystems::fingerprint;

use constant FINGERPRINTS_DIR => "fingerprints/";

Log::Log4perl::init($ENV{'LOG4PERLCONF'});
my $logger = Log::Log4perl->get_logger('fingerprint');

sub init {
	my ($self) = @_;

	$logger->debug("Initializing fingerprint subsystem");

	$self->{'fingerprints'} = {};
	
}

sub checkAbility {
	my ($self) = @_;

	$self->{'abilities'}{'fingerprint'} = $> ? 0 : 1;

}

sub _updateIpTables {
	my ($self) = @_;

	my ($honeyspy_in_output, $honeyspy_in_prerouting) = (
		$self->_searchForRegexInCmd('^honeyspy\W', 'iptables -t mangle -L OUTPUT -n'),
		$self->_searchForRegexInCmd('^honeyspy\W', 'iptables -t mangle -L PREROUTING -n')
	);

	system('iptables -t mangle -N honeyspy')
		unless ($honeyspy_in_output or $honeyspy_in_prerouting);
	system('iptables -t mangle -F honeyspy');

	system('iptables -t mangle -I OUTPUT 1 -j honeyspy')
		unless ($honeyspy_in_output);
	system('iptables -t mangle -I PREROUTING 1 -j honeyspy')
		unless ($honeyspy_in_prerouting);

	while ((my ($ip, $os) = each(%{$self->{'fingerprints'}}))) {
		next unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		next unless $os =~ /^[[:alnum:]\._\-]+$/;

		system("iptables -t mangle -A honeyspy -d $ip -j PERS "
		. "--tweak dst --local --conf " . FINGERPRINTS_DIR . "/$os.conf") >> 8 == 0
			or return "Couldn't set $os fingerprint on $ip";
		system("iptables -t mangle -A honeyspy -s $ip -j PERS "
		. "--tweak src --local --conf " . FINGERPRINTS_DIR . "/$os.conf") >> 8 == 0
			or return "Couldn't set $os fingerprint on $ip";
	}

	return 0;
}

sub setFingerprint {
	my ($self, $addr, $os) = @_;
	$logger->info("Setting $os fingerprint on $addr");

	my $fpr_file = FINGERPRINTS_DIR . "/$os.conf";

	if (! -f $fpr_file or ! -r $fpr_file) {
		my $msg = "No suck file for $os stack fingerprint";
		$logger->error($msg);
		return $msg;
	}

	$self->{'fingerprints'}{$addr} = $os;
	return $self->_updateIpTables();
}

sub delFingerprint {
	my ($self, $addr) = @_;

	if ($addr) {
		$logger->info("Disabling fingerprint mangling on $addr");
		delete $self->{'fingerprints'}{$addr};
	}
	else {
		$logger->info("Disabling fingerprint mangling");
		$self->{'fingerprints'} = {};
	}

	return $self->_updateIpTables();
}

sub getAvailableFingerprints {
	my ($self) = @_;

	if (!opendir(DIR, FINGERPRINTS_DIR)) {
		my $err = "Couldn't open " . FINGERPRINTS_DIR;
		$logger->error($err);
		return $err;
	}

	my @result;

	foreach (readdir(DIR)) {
		next unless /.+\.conf$/;
		my $os = $_;
		$os =~ s/\.conf$//;
		push(@result, $os);
	}
	closedir(DIR);

	return @result;
}


1;

