#!/usr/bin/perl

=head1 NAME

00_base.t - Check basic functionality of File::KeePass

=cut

use strict;
use warnings;
use Test::More tests => 35;

use_ok('File::KeePass');

my $pass = "foo";
my $obj  = File::KeePass->new;
ok(!eval { $obj->groups }, "No groups until we do something");
ok(!eval { $obj->header }, "No header until we do something");

###----------------------------------------------------------------###

# create some new groups
my $g_id = $obj->add_group({
    title => 'Foo',
    icon  => 1,
});
ok($g_id, "Could add a group");
ok($obj->groups, "Now we have groups");
ok(!eval { $obj->header }, "Still no header until we do something");
ok(my $g = $obj->find_group({id => $g_id}), "Found a group");
is($g->{'title'}, 'Foo', "Was the same group");

my $g_id2 = $obj->add_group({
    title => 'Bar',
    group => $g_id,
});
ok(my $g2 = $obj->find_group({id => $g_id2}), "Found a child group");
is($g2->{'title'}, 'Bar', "Was the same group");

# try adding an entry
my $e_uuid  = $obj->add_entry({title => 'bam', password => 'flimflam'});
ok($e_uuid, "Added an entry");
my $e_uuid2 = $obj->add_entry({title => 'bim', username => 'BIM'});

my @e = $obj->find_entries({title => 'bam'});
is(scalar(@e), 1, "Found one entry");
is($e[0]->{'uuid'}, $e_uuid, "Is the right one");

###----------------------------------------------------------------###

# turn it into the binary encrypted blob
my $db = $obj->gen_db($pass);
ok($db, "Gened a db");

###----------------------------------------------------------------###

# now try parsing it and make sure it is still in ok form
$obj->auto_lock(0);
my $ok = $obj->parse_db($db, $pass);
ok($ok, "Re-parsed groups");
ok($obj->header, "We now have a header");

ok($g = $obj->find_group({id => $g_id}), "Found a group in parsed results");
is($g->{'title'}, 'Foo', "Was the correct group");

my $e = eval { $obj->find_entry({title => 'bam'}) };
ok($e, "Found one entry");
is($e->{'uuid'}, $e_uuid, "Is the right one");


###----------------------------------------------------------------###

# test locking and unlocking
ok(!$obj->is_locked, "Object isn't locked");
is($e->{'password'}, 'flimflam', 'Had a good unlocked password');

$obj->lock;
ok($obj->is_locked, "Object is now locked");
is($e->{'password'}, undef, 'Password is now hidden');
is($obj->locked_entry_password($e), 'flimflam', 'Can access single password');
is($e->{'password'}, undef, 'Password is still hidden');

$obj->unlock;
ok(!$obj->is_locked, "Object isn't locked");
is($e->{'password'}, 'flimflam', 'Had a good unlocked password again');


# make sure auto_lock does come one
$obj->auto_lock(1);
$ok = $obj->parse_db($db, $pass);
ok($ok, "Re-parsed groups");
ok($obj->is_locked, "Object is auto locked");


###----------------------------------------------------------------###

# test file operations
$obj->unlock;
my $file = __FILE__.".kdb";

$obj->save_db($file, $pass);
ok(-e $file, "File now exists");
$obj->clear;
ok(!eval { $obj->groups }, "Cleared out object");

ok($obj->load_db($file, $pass), "Loaded from file");

ok($g = $obj->find_group({id => $g_id}), "Found a group in parsed results");
is($g->{'title'}, 'Foo', "Was the correct group");

unlink($file);
unlink("$file.bak");

###----------------------------------------------------------------###
