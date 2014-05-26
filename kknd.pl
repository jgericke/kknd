# 	- kknd alpha 0.3 -
#
#	   20/01/2010		
# 
#	  JB Gericke
#   julian@sasquatchpie.co.za
#
# Changelog:
#   Removed fast search
#
#!/usr/bin/perl
use strict;
use feature qw(switch);
use IPTables::libiptc;
use Config::Simple;
use Daemon::Generic;

sub ip_drop;
sub ip_reject;
sub ip_handler;
sub read_blacklist;
sub read_whitelist; 
sub persist_shitlist;
sub create_chain;
sub gd_preconfig;
sub gd_run;

my $conf                = {};
my $confimport          = "/usr/local/etc/kknd/kknd.conf";
my $pipe; 
my $whitelist;
my $shitlist;
my $scan_threshold;
my $persist_black;
my $ip_action;
my $reject_type;
my %ip_counter=();

newdaemon(
  progname		=> 'kknd',
  pidfile		=> '/var/run/kknd.pid',
  version		=> '0.3',
  logpriority		=> 'user.info', 
);

sub ip_reject {
  my $ip_in = $_[0];
  my $chain = "kknd";
  my $success;
  my $table = IPTables::libiptc::init('filter');
  if(not defined $table) {
   print STDERR "Initialising $table failed\n";
   exit(0);
  }
  my @reject_source = ("-I", "$chain", "-s", "$ip_in", "-j", "REJECT", "--reject-with", "$reject_type");
  if( $success = $table->iptables_do_command(\@reject_source)) {
   print STDOUT "Rejecting traffic from $ip_in with type $reject_type\n";
  } else {
   print STDERR "Failure to run command $ip_in REJECT $reject_type\n";
  }
  if(!$table->commit()) {
    print STDERR "Failure committing ipt changes\n";
  }
}

sub ip_drop {
  my $ip_in = $_[0];
  my $chain = "kknd";
  my $success;
  my $table = IPTables::libiptc::init('filter');
  if(not defined $table) {
   print STDERR "Initialising $table failed\n";
   exit(0);
  }
  my @drop_source = ("-I", "$chain", "-s", "$ip_in", "-j", "DROP");
  if( $success = $table->iptables_do_command(\@drop_source)) {
   print STDOUT "Dropping traffic from $ip_in\n";
  } else {
   print STDERR "Failure to run command $ip_in DROP\n";
  }
  if(!$table->commit()) {
    print STDERR "Failure committing ipt changes\n";
  }
}

sub ip_handler {
  my $ip_in = $_[0];
  if($ip_counter{$ip_in} gt 0) { 
   $ip_counter{$ip_in} += 1;
  } else {
   $ip_counter{$ip_in} = 1;
  }
  if($ip_counter{$ip_in} > $scan_threshold) {
   print STDOUT "$ip_in - past threshold - blacklisting\n";
   open(BLACKLIST,">>$shitlist");
   print BLACKLIST "$ip_in\n";
   close BLACKLIST;
   given ($ip_action) { 
    when('drop') { ip_drop($ip_in); }
    when('reject') { ip_reject($ip_in); }
    default { ip_drop($ip_in); }
   }
  }
}

sub read_blacklist {
  my $ip_in = $_[0];
  my $ip_found = 0;
  open(BLACKLIST,"<$shitlist");
  while(my $line = <BLACKLIST>) {
    chomp($line);
    if($line eq $ip_in) {
     $ip_found = 1;
    }
  }
  if(!$ip_found) {
   ip_handler($ip_in);
  }
}

sub read_whitelist {
  my $ip_in = $_[0];
  my $ip_found = 0;
  open(WHITELIST,"<$whitelist");
  while(my $line = <WHITELIST>) {
    chomp($line);
    if($line eq $ip_in) {
     $ip_found = 1;
    }
  }
  if(!$ip_found) {
   read_blacklist($ip_in);
  }
}

sub create_chain {
  my $chain = "kknd";
  my $success;
  my $table = IPTables::libiptc::init('filter');
  if(not defined $table) {
   print STDERR "Initialising $table failed\n";
   exit(0);
  }
  if(!$table->is_chain("$chain")) {
   if($success = $table->create_chain("$chain")) {
    print STDOUT "Chain $chain created successfully\n";
   } else {
    print "Failed to create chain $chain\n";
    exit(0);
   }
  } else {
    print STDOUT "Chain $chain exists, will flush\n";
    my @flush_chain = ("-F", "$chain");
    if($success = $table->iptables_do_command(\@flush_chain)) {
     print STDOUT "Flushed existing chain $chain\n";
    } else {
     print STDERR "An error occurred flushing $chain\n";
     exit(0);
    }
  } 
  my @rm_input = ("-D", "INPUT", "-j", "$chain");
  if($success = $table->iptables_do_command(\@rm_input)) {
   print STDOUT "Caught existing filter on INPUT, removed\n";
  } else {
   print STDOUT "No existing filter on INPUT/$chain, will create\n";
  }
  my @set_input = ("-I", "INPUT", "-j", "$chain");
  if($success = $table->iptables_do_command(\@set_input)) {
   print STDOUT "Filtering INPUT through $chain\n";
  } else {
   print STDERR "Failed to add rule\n";
   exit(0);
  }
  if($table->commit()) {
   print STDOUT "Ready to rock\n";
  } else {
   print STDERR "Failure committing ipt changes\n";
  }
}

sub persist_shitlist {
  my $dupecheck = $shitlist . ".dupe"; 
  my %dupetmp;
  open(ORIG,"<$shitlist") or die "Failed to open $shitlist";
  open(DUPE,">$dupecheck") or die "Failed to create $dupecheck";
  while(my $dupeline = <ORIG>) {
   next if $dupeline =~ m/^\s*$/;
   print DUPE $dupeline unless($dupetmp{$dupeline}++);
  }
  close(DUPE);
  close(ORIG);
  rename $dupecheck, $shitlist;
  if($persist_black) {
   open(BLACKLIST,"<$shitlist") or die "Failed to open $shitlist";
   while(my $line = <BLACKLIST>) {
     $line =~ s/^\s+//;
     $line =~ s/\s+$//;
     ip_drop($line);
    print STDOUT "$line found in $shitlist - dropping\n";
   }
   close(BLACKLIST);
  }
}

sub gd_preconfig {
  if(! -e $confimport) {
   print STDERR "Failed to open $confimport\n";
   exit(0);
  } else {
   Config::Simple->import_from($confimport, $conf);
   $pipe                = $conf->{"env.pipe"};
   $whitelist           = $conf->{"env.whitelist"};
   $shitlist            = $conf->{"env.shitlist"};
   $scan_threshold      = $conf->{"calib.scan_threshold"};
   $persist_black       = $conf->{"calib.persist_black"};
   $ip_action           = $conf->{"calib.ip_action"};
   $reject_type         = $conf->{"calib.reject_type"};
   return();
  }
}

sub gd_run {
  print STDOUT "Starting kknd at ".localtime()."\n";
  create_chain;
  persist_shitlist;
  open(FIFO,"<$pipe") or die "Failed to open $pipe";
  while(my $line = <FIFO>) {
   my $ip = (split /SRC=/,((split / /, $line)[17]))[1];
   read_whitelist($ip);
  } 
  close FIFO
}

gd_preconfig;
gd_run;
