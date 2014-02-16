#!/usr/bin/perl -w
#=============================================================================
# Copyright © 2009 Jason Heddings.  All rights reserved.
# $Id: x10d.pl 44 2010-12-12 04:10:14Z jheddings $
#=============================================================================

use strict;
use Data::Dumper;
use DateTime;
use File::Path;
use Sys::Syslog;

# set config defaults
my %config = (
  conf => '/etc/x10d.conf',
  schedule => '/etc/x10d.conf',
  location => undef,
  port => '/dev/ttyS0',
  units => 'metric',
  daemon => 0,
  br => 'br',
);

# internal data for the application
my %appdata = (
  apprun => 1,
  status => 0,
  isdaemon => 0,
  enabled => 1,

  # XXX maybe as config options
  rundat => '/var/run/x10d',
  pidfile => '/var/run/x10d/pid',
);

# the schedule
my $sched = Scheduler->new();

# weather provider
my $wx = undef;

# locking mechanism
my $pidfile = undef;

################################################################################
# print log message at given level using system logging facility
sub logit {
  my $pri = shift;
  syslog($pri, @_);
}

################################################################################
# display version information and exit
sub version {
  print '$Id: x10d.pl 44 2010-12-12 04:10:14Z jheddings $', "\n";
  exit (shift || 0);
}

################################################################################
# display usage and exit with a status code
sub usage {
  print STDERR << "EOF";
usage: x10d.pl [<options>]

where options include:
  -d         : run server as a daemon
  -f <file>  : specify config file
  -q <query> : query for a location and exit
  -h         : display help and exit
  -v         : display version and exit
EOF

  exit (shift || 0);
}

################################################################################
# parse command line options
sub parse_cmdline_opts {
  use Getopt::Std;

  my %opts;
  getopts('df:q:hv', \%opts) || usage(1);
  usage(0) if ($opts{h});
  version() if ($opts{v});

  if ($opts{q}) {
    search($opts{q});
    exit 0;
  }

  if ($opts{f}) {
    $config{conf} = $opts{f};
    $config{schedule} = $opts{f};
  }

  if ($opts{d}) {
    $config{daemon} = 1;
  }
}

################################################################################
# load configuration file
sub load_configuration {
  logit('debug', 'reading config: %s', $config{conf});
  open(CFG, "<", $config{conf}) || die($!);
  while (<CFG>) {
    if (m/^%([^\s]*)\s=\s(.*)$/) {
      if (exists($config{$1})) {
        logit('debug', 'USER CONFIG: %s = %s', $1, $2);
        $config{$1} = $2;
      } else {
        die("invalid configuration directive at $. -- $1");
      }
    }
  }
  close(CFG);
}

################################################################################
# perform global initialization tasks
sub global_constructors {
  openlog('x10d', 'pid,cons', 'user');
  logit('info', 'x10d starting');

  # setup signal handlers
  $SIG{INT} = 'INT_handler';
  $SIG{HUP} = 'HUP_handler';
  $SIG{TERM} = 'TERM_handler';
  $SIG{USR1} = 'USR1_handler';

  parse_cmdline_opts();
  load_configuration();

  # create runtime data dir as needed
  unless (-d $appdata{rundat}) {
    logit('debug', 'creating runtime data directory: %s', $appdata{rundat});
    mkpath($appdata{rundat}) || die($!);
  }

  # XXX this feels a little late to set up the lock, we might need
  # to, though, since we may allow multiple instances based on config
  $pidfile = Pidfile->new($appdata{pidfile});
  $pidfile->lock() || die;

  # setup weather provider as needed
  if (defined($config{location})) {
    logit('debug', 'loading wx data cache');
    $wx = WxDataCache->new($config{location});
  }

  $sched->load($config{schedule});
}

################################################################################
# continue to execute process as a daemon
sub daemonize {
  use POSIX qw(setsid);

  defined(my $pid = fork()) || die($!);
  $appdata{isdaemon} = ($pid) ? 0 : 1;

  if ($appdata{isdaemon}) {
    $pidfile->relock();

    umask(0);
    chdir('/') || die($!);
    setsid || die($!);

    open(STDIN, '</dev/null') || die($!);
    open(STDOUT, '>/dev/null') || die($!);
    open(STDERR, '>/dev/null') || die($!);

  } else {
    logit('debug', 'parent process exiting');
    exit 0;
  }

  logit('debug', 'daemon process started');
}

################################################################################
sub search {
  my ($query) = @_;
  my @locations = WxDataCache::query($query);
  foreach (@locations) {
    next unless defined($_);
    printf("%s :: %s\n", $_->id(), $_->name());
  }
}

################################################################################
# returns the standard representation of the current time as a DateTime object
sub now {
  return DateTime->now(
    time_zone => 'local'
  );
}

################################################################################
# parses the ISO8601 string and returns a DateTime object
sub iso8601_as_dt {
  use DateTime::Format::ISO8601;
  my $str = shift || die;
  return DateTime::Format::ISO8601->parse_datetime($str);
}

################################################################################
# dumps the scheduler to a file or stdout
sub dump_sched {
  my $file = shift;

  $Data::Dumper::Indent = 1;
  if ($file) {
    open(FP, '>', $file) || return;
    print FP Data::Dumper->Dump([$sched], [qw(*sched)]);
    close(FP);
  } else {
    print Data::Dumper->Dump([$sched], [qw(*sched)]);
    print Data::Dumper->Dump([$wx], [qw(*sched)]);
  }
}

################################################################################
# TERM signal handler
sub TERM_handler {
  logit('debug', 'recieved signal: TERM');
  $appdata{apprun} = 0;
}

################################################################################
# INT signal handler
sub INT_handler {
  logit('debug', 'recieved signal: INT');
  logit('info', 'canceled by user');
  $appdata{apprun} = 0;
}

################################################################################
# HUP signal handler
sub HUP_handler {
  logit('debug', 'recieved signal: HUP');
  $appdata{enabled} = 0;
  $sched->reload();
  $appdata{enabled} = 1;
}

################################################################################
# USR1 signal handler
sub USR1_handler {
  logit('debug', 'recieved signal: USR1');
  dump_sched($appdata{rundat} . '/schedule');
}

################################################################################
package Pidfile; ###############################################################

sub new {
  my ($proto, $pidfile) = @_;
  my $self = {
    pidfile => $pidfile,
  };
  bless($self);
  return $self;
}

sub lock {
  my $self = shift || die;
  if (-f $self->{pidfile}) {
    my $pid = _read_pidfile($self->{pidfile});
    if (_pid_is_active($pid)) {
      die('x10d is already running: ', $pid);
    }
  }
  _write_pidfile($self->{pidfile});
  return 1;
}

sub unlock {
  my $self = shift || die;
  if (-f $self->{pidfile}) {
    unlink($self->{pidfile}) || die($!);
  }
}

sub relock {
  my $self = shift || die;
  unless (-f $self->{pidfile}) {
    die('pid file missing');
  }
  _write_pidfile($self->{pidfile});
  return 1;
}

sub active {
  my $self = shift || die;
  unless (-f $self->{pidfile}) {
    return undef;
  }
  return _read_pidfile($self->{pidfile});
}

sub _read_pidfile {
  my $pidfile = shift || die;
  open(PID, '<', $pidfile) || die($!);
  my $pid = <PID>;
  close(PID);
  return $pid;
}

sub _write_pidfile {
  my $pidfile = shift || die;
  open(PID, '>', $pidfile) || die($!);
  print PID $$;
  close(PID);
}

sub _pid_is_active {
  my $pid = shift || die;
  return (kill(0, $pid) > 0);
}

################################################################################
package Scheduler; #############################################################

sub new {
  my $proto = shift;
  my $self = {
    schedule => undef,
    filename => undef,
  };
  bless($self);
  return $self;
}

sub reload {
  my $self = shift || die;
  my $filename = $self->{filename};
  if (defined($filename)) {
    $self->{schedule} = _load($filename);
  }
}

sub load {
  my $self = shift || die;
  my ($filename) = @_;
  $self->{schedule} = _load($filename);
  $self->{filename} = $filename;
}

sub step {
  my $self = shift || die;
  return unless ($appdata{enabled});
  foreach (@{$self->{schedule}}) {
    $_->execute() if ($_->is_time());
  }
}

sub run_manual_jobs {
  my $self = shift || die;
  my ($pattern) = @_;
  ::logit('debug', 'run_manual_jobs %s', $pattern);
  foreach (@{$self->{schedule}}) {
    $_->execute() if ($_->{orig} =~ $pattern);
  }
}

sub _load {
  my ($file) = @_;
  my @schedule = ();

  ::logit('debug', 'reading schedule: %s', $file);
  open(SCHED, '<', $file) || die($!);
  while (<SCHED>) {
    # trim whitespace
    s/^\s*//; s/\s*$//;

    # ignore comments, config, and blanks
    next if (m/^([%#].*)?$/);

    ::logit('debug', 'SCHED: %s', $_);

    my $job = Job::create();
    if (defined($job)) {
      push(@schedule, $job);
    } else {
      ::logit('err', 'unrecognized entry: %s', $_);
    }
  }
  close(SCHED);
  return \@schedule;
}

################################################################################
package Job; ###################################################################

sub new {
  my ($proto, $orig, $id) = @_;
  my $self = {
    id => $id,
    orig => $orig,
    spec => undef,
    commands => undef,
    next_time => undef,
    last_time => undef,
  };
  bless($self);
  return $self;
}

sub execute {
  my $self = shift || die;
  ::logit('debug', 'run job: %s', $self->{orig});
  foreach (@{$self->{commands}}) { $_->exec(); }
  $self->{last_time} = ::now()->iso8601();
  $self->_update_next_time();
}

sub next_time {
  my $self = shift || die;
  return $self->{next_time};
}

sub last_time {
  my $self = shift || die;
  return $self->{last_time};
}

sub is_time {
  my $self = shift || die;
  my $is_time = undef;
  my $now = ::now();
  my $next = $self->{next_time};
  if (defined($next)) {
    $next = ::iso8601_as_dt($next);
    $is_time = ($next <= $now) ? 1 : 0;
  } elsif (defined($self->{spec})) {
    $is_time = $self->{spec}->is_time($now);
  }
  return $is_time;
}

sub _update_next_time {
  my $self = shift || die;
  my $spec = $self->{spec};
  $self->{next_time} = undef;
  if (defined($spec)) {
    my $next = $spec->next_time();
    if (defined($next)) {
      $self->{next_time} = $next->iso8601();
      ::logit('debug', 'next time: %s', $self->{next_time});
    }
  }
}

sub create {
  my $entry = shift || $_;

  unless ($entry =~ m/^((@[^\s]+)|({.+})|(\[.+\]))\s*(.*)$/) {
    return undef;
  }

  my @cmds;
  foreach (split(/\s*;\s*/, $5)) {
    my $cmd = Command::create();
    push(@cmds, $cmd);
  }

  my $job = new Job();
  $job->{orig} = $entry;
  $job->{id} = $.;
  $job->{spec} = Spec::create($1);
  $job->{commands} = \@cmds;
  $job->_update_next_time();

  # TODO validate job entries (i.e. commands & spec)

  return $job;
}

################################################################################
package HouseCmd; ##############################################################

use constant REGEX => qr/^([A-P])(1[0-6]|[1-9])?((_(ON|OFF))|([+-][0-9]*))$/;

sub new {
  my ($proto, $cmd) = @_;
  ($cmd =~ REGEX) || return;
  my $self = {
    orig => $cmd,
    house => $1,
    device => $2,
    action => $5 || $6,
  };
  bless($self);
  return $self;
}

sub exec {
  my $self = shift || die;
  my $house = $self->{house};
  my $device = $self->{device};
  my $action = $self->{action};

  ::logit('debug', 'EXEC: house -- %s%s %s', $house, $device, $action);
  my @args = ( '--port=' . $config{port}, '--house=' . $house );

  if ($action eq 'ON') {
    if (defined($device)) {
      push(@args, '--on=' . $device);
    } else {
      push(@args, '--ON');
    }
  } elsif ($action eq 'OFF') {
    if (defined($device)) {
      push(@args, '--off=' . $device);
    } else {
      push(@args, '--OFF');
    }
  } elsif ($action =~ m/^[+-][0-9]*$/) {
    push(@args, '--dim=' . $action);
    if (defined($device)) {
      $args[-1] .= ',' . $device;
    }
  } else {
    ::logit('err', 'invalid house command');
  }

  ::logit('debug', 'br: %s', join(' ', @args));
  system($config{br}, @args);
}

sub matches {
  foreach (@_) {
    return 0 unless ($_ =~ REGEX);
  }
  return 1;
}

################################################################################
package Command; ###############################################################

sub create {
  my $str = shift || $_;

  (NullCmd::matches($str)) && return NullCmd->new($str);
  (HouseCmd::matches($str)) && return HouseCmd->new($str);

  return undef;
}


################################################################################
package NullCmd; ###############################################################

use constant REGEX => qr/^<(null|nop|noop|sleep)\s*(\d+)?>$/;

sub new {
  my ($proto, $cmd) = @_;
  ($cmd =~ REGEX) || return;
  my $self = {
    orig => $cmd,
    delay => $2,
  };
  bless($self);
  return $self;
}

sub exec {
  my $self = shift || die;
  ::logit('debug', 'EXEC: %s', $self->{orig});

  my $delay = $self->{delay};
  if (defined($delay)) { sleep($delay); }
}

sub matches {
  foreach (@_) {
    return 0 unless ($_ =~ REGEX);
  }
  return 1;
}

################################################################################
package Spec; ##################################################################

sub create {
  my $str = shift || $_;

  # handle pre-defined specs here (and offsets / options)
  if ($str =~ m/^@([a-z]+)(([+-][0-9]+)|(\((.*)\)))?$/) {
    ($1 eq 'yearly') && return CronSpec->new('{0 0 1 1 *}');
    ($1 eq 'monthly') && return CronSpec->new('{0 0 1 * *}');
    ($1 eq 'weekly') && return CronSpec->new('{0 0 * * 0}');
    ($1 eq 'hourly') && return CronSpec->new('{0 * * * *}');
    ($1 eq 'midnight') && return CronSpec->new('{0 0 * * *}');
    ($1 eq 'noon') && return CronSpec->new('{0 12 * * *}');
    ($1 eq 'sunrise') && return SolarSpec->new('sunrise', $2);
    ($1 eq 'sunset') && return SolarSpec->new('sunset', $2);

  } elsif (CronSpec::matches($str)) {
    return CronSpec->new($str);

  } elsif (ConditionalSpec::matches($str)) {
    return ConditionalSpec->new($str);
  }

  return undef;
}

################################################################################
package CronSpec; ##############################################################

use Set::Crontab;

use constant REGEX => qr/^\{\s*([0-9,*-]*(\s*[0-9,*-]*){4})\s*\}$/;

sub new {
  my ($proto, $spec) = @_;
  ($spec =~ REGEX) || return;
  my @fields = split(/\s+/, $1);
  my $self = {
    orig => $spec,
    minutes => Set::Crontab->new($fields[0], [0..59]),
    hours => Set::Crontab->new($fields[1], [0..23]),
    days => Set::Crontab->new($fields[2], [1..31]),
    months => Set::Crontab->new($fields[3], [1..12]),
    wdays => Set::Crontab->new($fields[4], [0..6]),
  };
  bless($self);
  return $self;
}

sub is_time {
  my $self = shift || die;
  die "we shouldn't be here";
}

sub next_time {
  my $self = shift || die;
  my $dt = ::now();

  # skip past the current minute, reset seconds
  $dt->add(minutes => 1)->set(second => 0);

  # http://tinyurl.com/canztx (loopy version)
  for (my $try = 0; $try < 256; $try++) {
    unless ($self->{months}->contains($dt->month)) {
      $dt->add(months => 1)->set(day => 1, hour => 0, minute => 0);
      next;
    }
    unless ($self->{days}->contains($dt->day)) {
      $dt->add(days => 1)->set(hour => 0, minute => 0);
      next;
    }
    unless ($self->{wdays}->contains($dt->wday % 7)) {
      $dt->add(days => 1)->set(hour => 0, minute => 0);
      next;
    }
    unless ($self->{hours}->contains($dt->hour)) {
      $dt->add(hours => 1)->set(minute => 0);
      next;
    }
    unless ($self->{minutes}->contains($dt->minute)) {
      $dt->add(minutes => 1);
      next;
    }
    ::logit('debug', 'resolved %s in %d moves', $self->{orig}, $try);
    return $dt;
  }

  ::logit('debug', 'unable to resolve %s', $self->{orig});
  return undef;
}

sub matches {
  foreach (@_) {
    return 0 unless ($_ =~ REGEX);
  }
  return 1;
}

################################################################################
package SolarSpec; #############################################################

sub new {
  my ($proto, $event, $offset) = @_;
  my $self = {
    event => $event,
    offset => $offset,
  };
  bless($self);
  return $self;
}

sub is_time {
  my $self = shift || die;
  die "we shouldn't be here";
}

sub next_time {
  my $self = shift || die;
  my $next = undef;

  # because these events are provided by the weather provider, we rely on it to
  # give a reasonable response based on the current time, i.e. never in the past

  if ($self->{event} eq 'sunrise') {
    $next = $wx->sunrise();
  } elsif ($self->{event} eq 'sunset') {
    $next = $wx->sunset();
  }

  if ((defined($next)) && ($self->{offset})) {
    $next->add(minutes => $self->{offset});
  }

  return $next;
}

################################################################################
package ConditionalSpec; #######################################################

use constant REGEX => qr/^\[(.+)\]$/;

sub new {
  my ($proto, $spec) = @_;
  ($spec =~ REGEX) || return;
  my $expr = _expand($1);
  my $self = {
    expr => $expr,
    prev => undef,
  };
  bless($self);
  return $self;
}

sub is_time {
  my $self = shift || die;
  my ($time) = @_; #unused

  my $curr = eval($self->{expr});
  my $prev = $self->{prev};

  $self->{prev} = $curr;
  return ($curr && (! $prev));
}

sub next_time {
  my $self = shift || die;
  return undef;
}

sub matches {
  foreach (@_) {
    return 0 unless ($_ =~ REGEX);
  }
  return 1;
}

sub _expand {
  my $expr = shift;

  $expr =~ s/true/1/ig;
  $expr =~ s/false/0/ig;

  # TODO this doesn't support multiple params to _cond_XX
  $expr =~ s/([\w]+)\(([^\)]*)\)/_cond_$1\('$2'\)/ig;

  return $expr;
}

sub _cond_wx {
  my $param = shift;
  ($param eq 'temp') and return $wx->temperature;
  ($param eq 'hot') and return $wx->temperature > 30;
  ($param eq 'cold') and return $wx->temperature < 0;
  ($param eq 'warm') and return ($wx->temperature >= 0) && ($wx->temperature <= 30);

  ($param eq 'wind') and return $wx->wind_speed;
  return 0; # this might cause strange behavior
}

sub _cond_is {
  # TODO we might support features here someday
  return 0; # this might cause strange behavior
}

################################################################################
package WxDataCache; ###########################################################

use Weather::Com;
use Weather::Com::Finder;
use Weather::Com::Location;

# registered for this application
use constant XOAP_LICENSE => 'ce31bf38808de0fe';
use constant XOAP_PARTNER_ID => '1000457173';

# shared provider of weather data
my $_provider = undef;

# shared finder
my $_finder = undef;

sub new {
  my ($proto, $loc) = @_;
  _init_location($loc);
  my $self = {
    location => $loc,
  };
  bless($self);
  return $self;
}

sub sunrise {
  my $self = shift || die;
  return _dt($_provider->sunrise());
}

sub sunset {
  my $self = shift || die;
  return _dt($_provider->sunset());
}

sub temperature {
  my $self = shift || die;
  my $cc = $_provider->current_conditions();
  return ($cc) ? $cc->temperature() : undef;
}

sub wind_speed {
  my $self = shift || die;
  my $cc = $_provider->current_conditions();
  my $wind = ($cc) ? $cc->wind() : undef;
  return ($wind) ? $wind->speed() : undef;
}

sub query {
  my ($query) = @_;
  $_finder = Weather::Com::Finder->new(
    partner_id => XOAP_PARTNER_ID,
    license => XOAP_LICENSE,
    cache => _init_cache(),
  );
  return $_finder->find($query);
}

sub _init_location {
  my $loc = shift || die;

  ::logit('debug', 'new wx location :: %s', $loc);
  $_provider = Weather::Com::Location->new(
    location_id => $loc,
    partner_id => XOAP_PARTNER_ID,
    license => XOAP_LICENSE,
    cache => _init_cache(),
    units => ($config{units} eq 'imperial') ? 's' : 'm',
  );

  my $cc = $_provider->current_conditions();
  # XXX would like to log the location name, but the Location class doesn't fill
  # it in unless passed via the constructor; requires a change to Weather::Com
  ::logit('debug', 'wx[%s] updated: %s', $loc, _dt($cc->last_updated()));
}

sub _init_cache {
  my $cache = $appdata{rundat} . '/wx';
  ::mkpath($cache) unless (-d $cache);
  return $cache;
}

sub _dt {
  my $wx_dt = shift || die;
  # TODO do need to handle the timezone in the weather data object?
  # Weather::Com::DateTime seems to provide the epoch in local time
  return DateTime->from_epoch(
    time_zone => 'local',
    epoch => $wx_dt->epoc(),
  );
}

################################################################################
package main; ##################################################################

# XXX see note in BEGIN
global_constructors();

BEGIN {
  # XXX this doesn't work here because we depend on %config data
  # to be initialized, but BEGIN runs before the data initializers
  # it would be nice if we could mirror the END block here...
  #global_constructors();
}

END {
  if ($pidfile && ($pidfile->active == $$)) {
    logit('info', 'x10d shutting down');

    $wx = undef;
    $sched = undef;

    $pidfile->unlock();
    closelog();
  }
}

$sched->run_manual_jobs(qr/^\@startup/);
if ($config{daemon}) { daemonize(); }

logit('info', 'x10d running');
while($appdata{apprun}) {
  my $next = ::now();

  # loop at the beginning of the next minute
  $next->add(minutes => 1)->set(second => 0);

  $sched->step();
  my $stop = ::now();

  if ($next > $stop) {
    my $delta = $next - $stop;
    sleep($delta->seconds);
  }
}

$sched->run_manual_jobs(qr/^\@shutdown/);

__END__
