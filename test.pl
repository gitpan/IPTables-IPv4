# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..23\n"; }
END {print "not ok 1\n" unless $loaded;}
use IPTables::IPv4;
my $testiter = 0;
$loaded = 1;
print "ok ", ++$testiter, "\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$table = IPTables::IPv4::init('filter');
if(!defined($table)) {
	print("\$table = $table\n");
	print("IPTables::IPv4::init() failed: $!\n");
	print("not ok ", ++$testiter, "\n");
	exit();
}

print("ok ", ++$testiter, "\n");

if(!($table->set_policy('FORWARD', 'DROP'))) {
	print("set_policy failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!($table->set_policy('FORWARD', 'DROP', {pcnt => 200, bcnt => 10000}))) {
	print("set_policy failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!($isachain = $table->is_chain('FORWARD'))) {
	print("not ");
}
print("ok ", ++$testiter, "\n");

print("FORWARD is ", ($isachain ? "" : "not "), "a chain.\n");

if($isachain = $table->is_chain('blabla')) {
	print("not ");
}
print("ok ", ++$testiter, "\n");

print("blabla is ", ($isachain ? "" : "not "), "a chain.\n");

if($table->append_entry('INPUT', {proto => "!tcp", jump => "REJECT", 'reject-with' => "tcp-reset"})) {
	print("append_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

@rules = $table->list_rules('INPUT');

$table->flush_entries('INPUT');

for $rule (@rules) {
	for $key (keys(%$rule)) {
		print("$key => '", $rule->{$key}, "', ");
	}
	print("\n");
	if(exists $$rule{'matches'}) {
		print("\tMatch list: ", join(", ", @{$$rule{'matches'}}), "\n");
	}
	$table->append_entry('INPUT', $rule) || die($!);
}

if(!$table->create_chain('test')) {
	print("create_chain() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->append_entry('test', {source => '!10.0.0.0/18', fragment => 1, 'in-interface' => 'eth0'})) {
	print("append_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->insert_entry('test', {source => '192.168.0.0/16', protocol => 'tcp'}, 0)) {
	print("insert_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->replace_entry('test', {source => '207.109.100.0/28', protocol => 'tcp', 'destination-port' => 22, jump => 'ACCEPT', 'tcp-option' => '!33', 'tcp-flags' => {inv => '', mask => ['SYN', 'ACK', 'RST'], comp => ['SYN']}}, 0)) {
	print("replace_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->append_entry('test', {protocol => 'icmp', 'in-interface' => 'eth0', jump => 'DROP', 'icmp-type' => '15/22-30'})) {
	print("append_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->append_entry('test', {source => '192.168.0.0/16', protocol => 'tcp', matches => ['mport'], 'destination-ports' => ['50:80',120,'180:330']})) {
	print("insert_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->insert_entry('INPUT', {protocol => '!7', jump => 'test'}, 0)) {
	print("insert_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->create_chain('test2')) {
	print("create_chain() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->insert_entry('test', {jump => 'test2'}, 0)) {
	print("insert_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

$i = 1;
@chains = $table->list_chains();
if(!@chains) {
	print("not ok ", ++$testiter, "\n");
	exit();
}
print("ok ", ++$testiter, "\n");

if(!$table->delete_entry('test', {source => '!10.0.0.0/18', fragment => 1, 'in-interface' => 'eth0'})) {
	print("delete_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

for $cnam (@chains) {
	print("Chain ", $i++, ": $cnam");
	if($table->builtin($cnam)) {
		($pol, $pcount, $bcount) = $table->get_policy($cnam);
		print(", default policy is $pol, $pcount packets, $bcount bytes");
	}
	else {
		$refcount = $table->get_references($cnam);
		print(", refcount is ", $refcount);
	}
	print("\n");
	$j = 1;
	for $rule ($table->list_rules($cnam)) {
		print("\tRule ", $j++, ": ");
		for $i (keys(%$rule)) {
			print("$i => ");
			my $r = $$rule{$i};
			if(ref($r) eq "ARRAY") {
				print("[", join(', ', @$r), "]");
			}
			else {
				print("'$r'");
			}
			print(", ");
		}
		print("\n");
		print("\tTCP flags: ",
			((exists $$rule{'tcp-flags'}->{'inv'}) ? "!" : ""),
			join(',', @{$$rule{'tcp-flags'}->{'mask'}}),
			"/", join(',', @{$$rule{'tcp-flags'}->{'comp'}}), "\n")
			if exists $$rule{'tcp-flags'};
	}
}

if(!$table->delete_num_entry('test', 0)) {
	print("delete_num_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->delete_num_entry('INPUT', 0)) {
	print("delete_num_entry() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->flush_entries('test')) {
	print("flush_entries() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->delete_chain('test')) {
	print("delete_chain() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->delete_chain('test2')) {
	print("delete_chain() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");

if(!$table->commit()) {
	print("commit() failed: $!\n");
	print("not ");
}
print("ok ", ++$testiter, "\n");
