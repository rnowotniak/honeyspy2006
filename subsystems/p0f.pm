#!/usr/bin/perl -w

use strict;
use Log::Log4perl;

package subsystems::p0f;

Log::Log4perl::init($ENV{'LOG4PERLCONF'});
my $logger = Log::Log4perl->get_logger('p0f');


sub init {
	my ($self) = @_;

	$logger->debug("Initializing p0f subsystem");

	$self->{'p0f_pid'} = undef,
	$self->{'p0f_fh'} = undef,
	$self->{'p0f_opts'} = {
			'fuzzy' => '0',
			'promiscuous' => '1',
			'masq_detection' => '0',
			'mode' => '0'
		};
	
}

sub checkAbility {
	my ($self) = @_;

	$self->{'abilities'}{'p0f'} = 0;

	foreach (split(/:/, $ENV{'PATH'})) {
		if (-x "$_/p0f") {
			$self->{'abilities'}{'p0f'} = 1;
			last;
		}
	}
}

############################################################
# Pasywne rozpoznawanie zdalnego systemu operacyjnego (p0f)
#
sub enableP0f {
	my ($self) = @_;
	$logger->info('Enabling p0f...');

	my ($rdfh, $wrfh);
	eval {
		my $args = '';
		$args .= '-F ' if $self->{'p0f_opts'}{'fuzzy'};
		$args .= '-p ' if $self->{'p0f_opts'}{'promiscuous'};
		$args .= '-M ' if $self->{'p0f_opts'}{'masq_detection'};
		my $mode = $self->{'p0f_opts'}{'mode'};
		$args .= '-A ' if $mode == 1;
		$args .= '-R ' if $mode == 2;

		use IPC::Open2;
		my $pid = open2($rdfh, $wrfh, "p0f -q -l $args 2>&1");

		$self->{'p0f_pid'} = $pid;
		$self->{'p0f_fh'} = $rdfh;
		$self->_addfh($rdfh, 'r');
		$self->{'r_handlers'}{$rdfh} = sub {
			$logger->info("OS recognized: " . <$rdfh>);
		};
	};
	for ($@) {
		if ($_) {
			my $msg = "Couldn't start p0f: $_";
			$logger->error($msg);
			return $msg;
		}
	}
}

sub disableP0f {
	my ($self) = @_;
	$logger->info('Disabling p0f...');

	if (defined $self->{'p0f_fh'}) {
		$self->_removefh($self->{'p0f_fh'});
		$self->{'p0f_fh'} = undef;
	}

	CORE::kill 9, $self->{'p0f_pid'}
		if defined $self->{'p0f_pid'};
}

sub setP0fOption {
	my ($self, %opts) = @_;

	$self->{'p0f_opts'}{$_} = $opts{$_}
		foreach (keys %opts);

	if ($self->{'p0f_fh'}) {
		$self->disableP0f();
		$self->enableP0f();
	}

	return 0;
}

1;

