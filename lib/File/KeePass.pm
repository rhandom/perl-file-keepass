package File::KeePass;

=head1 NAME

File::KeePass - Interface to KeePass V1 database files

=cut

use strict;
use warnings;
use Carp qw(croak);
use Crypt::Rijndael;
use Digest::SHA qw(sha256);
use CGI::Ex::Dump qw(debug);

use constant DB_HEADER_SIZE    => 124;
use constant PWM_DBSIG_1       => 0x9AA2D903;
use constant PWM_DBSIG_2       => 0xB54BFB65;
use constant PWM_DBVER_DW      => 0x00030002;
use constant PWM_FLAG_SHA2     => 1;
use constant PWM_FLAG_RIJNDAEL => 2;
use constant PWM_FLAG_ARCFOUR  => 4;
use constant PWM_FLAG_TWOFISH  => 8;

our $VERSION = '0.01';
my %locker;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub auto_lock {
    my $self = shift;
    $self->{'auto_lock'} = shift if @_;
    return !exists($self->{'auto_lock'}) || $self->{'auto_lock'};
}

###----------------------------------------------------------------###

sub load_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";

    open(my $fh, '<', $file) || croak "Couldn't open $file: $!\n";
    my $size = -s $file;
    read($fh, my $buffer, $size);
    close $fh;
    croak "Couldn't read entire file contents of $file.\n" if length($buffer) != $size;
    return $self->parse_db($buffer, $pass);
}

sub save_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";

    my $buf = $self->gen_db($pass);
    my $bak = "$file.bak";
    my $tmp = "$file.new.".int(time());
    open(my $fh, '>', $tmp) || croak "Couldn't open $tmp: $!\n";
    print $fh $buf;
    close $fh;
    croak "Written file size of $tmp didn't match - not moving into place";

    # try to move the file into place
    if (-e $bak) {
        unlink($bak) || croak "Couldn't removing already existing backup $bak: $!\n";
    }
    if (-e $file) {
        rename($file, $bak) || croak "Couldn't backup $file to $bak: $!\n";
    }
    rename($tmp, $file) || croak "Couldn't move $tmp to $file: $!\n";
    if (!$self->{'keep_backup'} && -e $bak) {
        unlink($bak) || croak "Couldn't removing temporary backup $bak: $!\n";
    }

    return 1;
}

###----------------------------------------------------------------###

sub parse_db {
    my ($self, $buffer, $pass) = @_;

    # parse and verify headers
    my $head = $self->parse_header($buffer);
    die "Wrong sig1 ($head->{'sig1'} != ".PWM_DBSIG_1().")\n" if $head->{'sig1'} != PWM_DBSIG_1;
    die "Wrong sig2 ($head->{'sig2'} != ".PWM_DBSIG_2().")\n" if $head->{'sig2'} != PWM_DBSIG_2;
    die "Unsupported File version ($head->{'ver'}).\n" if $head->{'ver'} & 0xFFFFFF00 != PWM_DBVER_DW & 0xFFFFFF00;
    my $enc_type = ($head->{'flags'} & PWM_FLAG_RIJNDAEL) ? 'rijndael'
                 : ($head->{'flags'} & PWM_FLAG_TWOFISH)  ? 'twofish'
                 : die "Unknown encryption type\n";

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    # decrypt the buffer
    my $crypto_size;
    my $orig_buffer;
    if ($enc_type eq 'rijndael') {
        my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
        $cipher->set_iv($head->{'enc_iv'});
        my $orig_size = length($buffer);
        $buffer = $cipher->decrypt(substr($buffer,DB_HEADER_SIZE));
        $orig_buffer = $buffer;
        my $extra = ord(substr $buffer, -1, 1);
        $crypto_size = $orig_size - DB_HEADER_SIZE - $extra;
        substr($buffer, $crypto_size, $orig_size-$crypto_size, ''); #$buffer = substr($buffer, 0, $crypto_size);
    } else {
        die "Unimplemented enc_type $enc_type";
    }
    croak "Decryption failed.\nThe key is wrong or the file is damaged.\n"
        if $crypto_size > 2**31 || (!$crypto_size && $head->{'n_groups'});
    croak "Checksum did not match.\nThe key is wrong or the file is damaged (or we need to implement utf8 input a bit better)\n"
        if $head->{'checksum'} ne sha256($buffer);

    # read the db
    my ($groups, $gmap, $pos) = $self->parse_groups($buffer, $head->{'n_groups'});
    $self->parse_entries($buffer, $head->{'n_entries'}, $pos, $gmap, $groups);

    $self->{'header'} = $head;

    $self->unlock if $self->{'groups'}; # make sure we don't leave dangling keys should we reopen a new db
    $self->{'groups'} = $groups;
    $self->lock if $self->auto_lock;
    return 1;
}

sub parse_header {
    my ($self, $buffer) = @_;
    my $size = length($buffer);
    croak "File was smaller than db header ($size < ".DB_HEADER_SIZE().")\n" if $size < DB_HEADER_SIZE;

    my @f = qw(sig1 sig2 flags ver seed_rand enc_iv n_groups n_entries checksum seed_key seed_rot_n);
    my $t =   'L    L    L     L   a16       a16    L        L         a32      a32      L';
    my %h; @h{@f} = unpack $t, $buffer;
    return \%h;
}

sub parse_groups {
    my ($self, $buffer, $n_groups) = @_;
    my $pos = 0;

    my @groups;
    my %gmap; # allow entries to find their groups (group map)
    my @gref = (\@groups); # group ref pointer stack - let levels nest safely
    my $previous_level = 0;
    my $group = {};
    while ($n_groups) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Group header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Group header offset is out of range. ($pos, $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $group->{'id'}     = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 2) {
            ($group->{'title'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 7) {
            $group->{'icon'}   = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 8) {
            $group->{'level'}  = unpack 'S', substr($buffer, $pos, 2);
        } elsif ($type == 0xFFFF) {
            $n_groups--;
            $gmap{$group->{'id'}} = $group;
            my $level = $group->{'level'} || 0;
            if ($previous_level > $level) {
                splice @gref, $previous_level, $previous_level - $level, ();
                push @gref, \@groups if !@gref;
            } elsif ($previous_level < $level) {
                push @gref, ($gref[-1]->[-1]->{'groups'} = []);
            }
            $previous_level = $level;
            push @{ $gref[-1] }, $group;
            $group = {};
        } else {
            $group->{'unknown'}->{$type} = substr($buffer, $pos, $size);
        }
        $pos += $size;
    }

    return (\@groups, \%gmap, $pos);
}

sub parse_entries {
    my ($self, $buffer, $n_entries, $pos, $gmap, $groups) = @_;

    my $entry = {};
    while ($n_entries) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Entry header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Entry header offset is out of range for type $type. ($pos, ".length($buffer).", $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $entry->{'uuid'}      = unpack 'H*', substr($buffer, $pos, $size);
        } elsif ($type == 2) {
            $entry->{'group_id'}  = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 3) {
            $entry->{'icon'}      = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 4) {
            ($entry->{'title'}    = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 5) {
            ($entry->{'url'}      = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 6) {
            ($entry->{'username'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 7) {
            ($entry->{'password'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 8) {
            ($entry->{'comment'}  = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 9) {
            $entry->{'created'}   = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xA) {
            $entry->{'modified'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xB) {
            $entry->{'accessed'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xC) {
            $entry->{'expires'}   = $self->parse_date(substr($buffer, $pos, $size));
	} elsif ($type == 0xD) {
            ($entry->{'bin_desc'} = substr($buffer, $pos, $size)) =~ s/\0$//;
	} elsif ($type == 0xE) {
            $entry->{'binary'}    = substr($buffer, $pos, $size);
        } elsif ($type == 0xFFFF) {
            $n_entries--;
            my $gid = delete $entry->{'group_id'};
            my $ref = $gmap->{$gid};
            if (!$ref) { # orphaned nodes go in special group
                $gid = -1;
                if (!$gmap->{$gid}) {
                    push @$groups, ($gmap->{$gid} = {id => $gid, title => '*Orphaned*', icon => 0});
                }
                $ref = $gmap->{$gid};
            }

            if ($entry->{'comment'} && $entry->{'comment'} eq 'KPX_GROUP_TREE_STATE') {
                if (!defined($entry->{'binary'}) || length($entry->{'binary'}) < 4) {
                    warn "Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error."
                } else {
                    my $n = unpack 'L', substr($entry->{'binary'}, 0, 4);
                    if ($n * 5 != length($entry->{'binary'}) - 4) {
                        warn "Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error.";
                    } else {
                        for (my $i = 0; $i < $n; $i++) {
                            my $group_id    = unpack 'L', substr($entry->{'binary'}, 4 + $i * 5, 4);
                            my $is_expanded = unpack 'C', substr($entry->{'binary'}, 8 + $i * 5, 1);
                            $gmap->{$group_id}->{'expanded'} = $is_expanded;
                        }
                    }
                }
                $entry = {};
                next;
            }

            push @{ $ref->{'entries'} }, $entry;
            $entry = {};
        } else {
            $entry->{'unknown'}->{$type} = substr($buffer, $pos, $size);
        }
        $pos += $size;
    }
}

sub parse_date {
    my ($self, $packed) = @_;
    my @b = unpack('C*', $packed);
    my $year = ($b[0] << 6) | ($b[1] >> 2);
    my $mon  = (($b[1] & 0b11)     << 2) | ($b[2] >> 6);
    my $day  = (($b[2] & 0b111111) >> 1);
    my $hour = (($b[2] & 0b1)      << 4) | ($b[3] >> 4);
    my $min  = (($b[3] & 0b1111)   << 2) | ($b[4] >> 6);
    my $sec  = (($b[4] & 0b111111));
    return sprintf "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $day, $hour, $min, $sec;
}

###----------------------------------------------------------------###

sub gen_date {
    my ($self, $date) = @_;
    return "\0\0\0\0\0" if ! $date;
    my ($year, $mon, $day, $hour, $min, $sec) = $date =~ /^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/ ? ($1,$2,$3,$4,$5,$6) : die "Invalid date ($date)";
    return pack('C*',
                ($year >> 6) & 0b111111,
                (($year & 0b111111) << 2) | (($mon >> 2) & 0b11),
                (($mon & 0b11) << 6) | (($day & 0b11111) << 1) | (($hour >> 4) & 0b1),
                (($hour & 0b1111) << 4) | (($min >> 2) & 0b1111),
                (($min & 0b11) << 6) | ($sec & 0b111111),
               );
}

sub gen_db {
    my $self = shift;
    my $pass = shift;
    croak "Missing pass\n" if ! defined($pass);
    my $groups = shift || $self->groups;
    croak "Please unlock before calling gen_db" if $self->is_locked($groups);
    my $head   = shift || {};

    srand((time() ^ $$) * rand()) if ! $self->{'srand'};
    foreach my $key (qw(seed_rand enc_iv)) {
        next if defined $head->{$key};
        $head->{$key} = '';
        $head->{$key} .= chr(int(255 * rand())) for 1..16;
    }
    $head->{'seed_key'}   = sha256(time.rand().$$) if ! defined $head->{'seed_key'};
    $head->{'seed_rot_n'} = 50_000 if ! defined $head->{'seed_rot_n'};

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    my $buffer  = '';
    my $entries = '';
    foreach my $g ($self->flat_groups($groups)) {
        $head->{'n_groups'}++;
        my @d = ([1,      pack('LL', 4, $g->{'id'} || 0)],
                 [2,      pack('L', length($g->{'title'})+1)."$g->{'title'}\0"],
                 [7,      pack('LL', 4, $g->{'icon'}  || 0)],
                 [8,      pack('LS', 2, $g->{'level'} || 0)],
                 [0xFFFF, pack('L', 0)]);
        push @d, [$_, $g->{'unknown'}->{$_}] for keys %{ $g->{'unknown'} || {} };
        $buffer .= pack('S',$_->[0]).$_->[1] for sort {$a->[0] <=> $b->[0]} @d;
        foreach my $e (@{ $g->{'entries'} || [] }) {
            $head->{'n_entries'}++;
            my @d = (
                     [1,      pack('LH*', length($e->{'uuid'})/2, $e->{'uuid'})],
                     [2,      pack('LL', 4, $g->{'id'}   || 0)],
                     [3,      pack('LL', 4, $e->{'icon'} || 0)],
                     [4,      pack('L', length($e->{'title'})+1)."$e->{'title'}\0"],
                     [5,      pack('L', length($e->{'url'})+1).   "$e->{'url'}\0"],
                     [6,      pack('L', length($e->{'username'})+1). "$e->{'username'}\0"],
                     [7,      pack('L', length($e->{'password'})+1). "$e->{'password'}\0"],
                     [8,      pack('L', length($e->{'comment'})+1).  "$e->{'comment'}\0"],
                     [9,      pack('L', 5). $self->gen_date($e->{'created'})],
                     [0xA,    pack('L', 5). $self->gen_date($e->{'modified'})],
                     [0xB,    pack('L', 5). $self->gen_date($e->{'accessed'})],
                     [0xC,    pack('L', 5). $self->gen_date($e->{'expires'})],
                     [0xD,    pack('L', length($e->{'bin_desc'})+1)."$e->{'bin_desc'}\0"],
                     [0xE,    pack('L', length($e->{'binary'})).$e->{'binary'}],
                     [0xFFFF, pack('L', 0)]);
            push @d, [$_, $e->{'unknown'}->{$_}] for keys %{ $e->{'unknown'} || {} };
            $entries .= pack('S',$_->[0]).$_->[1] for sort {$a->[0] <=> $b->[0]} @d;
        }
    }
    $buffer .= $entries; $entries = '';

    $head->{'checksum'} = sha256($buffer);
    $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($head->{'enc_iv'});
    my $extra = (16 - length($buffer) % 16) || 16; # always pad so we can always trim
    $buffer .= chr($extra) for 1 .. $extra;

    local $head->{'sig1'}  = PWM_DBSIG_1();
    local $head->{'sig2'}  = PWM_DBSIG_2();
    local $head->{'flags'} = PWM_FLAG_RIJNDAEL();
    local $head->{'ver'}   = PWM_DBVER_DW();
    my $header = $self->gen_header($head);
    my $enc    = $cipher->encrypt($buffer);

    return $header.$enc;
}

sub gen_header {
    my ($self, $args) = @_;
    local $args->{'n_groups'}  = $args->{'n_groups'}  || 0;
    local $args->{'n_entries'} = $args->{'n_entries'} || 0;
    my $header = ''
        .pack('L4', @{ $args }{qw(sig1 sig2 flags ver)})
        .$args->{'seed_rand'}
        .$args->{'enc_iv'}
        .pack('L2', @{ $args }{qw(n_groups n_entries)})
        .$args->{'checksum'}
        .$args->{'seed_key'}
        .pack('L', $args->{'seed_rot_n'});
    die "Invalid generated header\n" if length($header) != DB_HEADER_SIZE;
    return $header;
}

###----------------------------------------------------------------###

sub dump_groups {
    my ($self, $g, $indent) = @_;
    $indent = '' if ! $indent;
    print $indent.($g->{'expanded'} ? '-' : '+')."  $g->{'title'} ($g->{'id'})\n";
    $self->dump_groups($_, "$indent    ") for @{ $g->{'groups'} || [] };
    for my $e (@{ $g->{'entries'} || [] }) {
        print "$indent    > $e->{'title'}\t($e->{'uuid'})\n";
    }
}

sub groups { shift->{'groups'} || croak "No groups loaded yet\n" }

sub header { shift->{'header'} || croak "No header loaded yet\n" }

sub add_group {
    my ($self, $args, $parent_group, $top_groups) = @_;
    my $groups;
    my $level;
    $parent_group ||= delete $args->{'group'};
    if (defined $parent_group) {
        $parent_group = $self->find_group({id => $parent_group}, $top_groups) if ! ref($parent_group);
        if ($parent_group) {
            $groups = $parent_group->{'groups'} ||= [];
            $level  = $parent_group->{'level'}  || 0;
            $level++;
        }
    }
    $groups ||= $top_groups || ($self->{'groups'} ||= []);
    $level  ||= 0;

    my $gid;
    $gid = int((2**32-1) * rand()) while !$gid || $self->find_group({id => $gid});

    push @$groups, {
        title => defined($args->{'title'}) ? $args->{'title'} : '',
        icon  => $args->{'icon'} || 0,
        id    => $gid,
        level => $level,
    };

    return $gid;
}

sub find_group {
    my ($self, $args, $groups) = @_;
    die "Must specify one of id, title or icon" if !grep {defined $args->{$_}} qw(id title icon);
    for my $g (@{ $groups || $self->groups}) {
        if (   (!defined $args->{'id'}    || $g->{'id'}    eq $args->{'id'})
            && (!defined $args->{'title'} || $g->{'title'} eq $args->{'title'})
            && (!defined $args->{'icon'}  || $g->{'icon'}  eq $args->{'icon'})) {
            return $g;
        }
        next if ! $g->{'groups'};
        my $found = $self->find_group($args, $g->{'groups'});
        return $found if $found;
    }
    return;
}

sub flat_groups {
    my $self = shift;
    my $groups = shift || $self->groups;
    my @GROUPS;
    for my $g (@$groups) {
        push @GROUPS, $g;
        push @GROUPS, $self->flat_groups($g->{'groups'}) if $g->{'groups'};
    }
    return @GROUPS;
}

###----------------------------------------------------------------###

sub add_entry {
    my ($self, $args, $group, $groups) = @_;
    $groups ||= $self->groups;
    croak "You must unlock the passwords before adding new entries.\n" if $self->is_locked($groups);
    $args = {%$args};
    $group ||= delete($args->{'group'}) || $groups->[0] || $self->add_group({});
    if (! ref($group)) {
        $group = $self->find_group({id => $group}, $groups) || croak "Couldn't find a matching group to add entry to";
    }

    $args->{$_} = ''         for grep {!defined $args->{$_}} qw(title url username password comment bin_desc binary);
    $args->{$_} = 0          for grep {!defined $args->{$_}} qw(id icon);
    $args->{$_} = $self->now for grep {!defined $args->{$_}} qw(created accessed modified);;
    $args->{'expires'} ||= '2999-12-31 23:23:59';
    $args->{'uuid'} = unpack 'H32', sha256(time.rand().$$) while !$args->{'uuid'} || $self->find_entries({uuid => $args->{'uuid'}}, $groups);

    push @{ $group->{'entries'} ||= [] }, $args;
    return $args->{'uuid'};
}

sub flat_entries {
    my $self = shift;
    return (map { @{ $_->{'entries'} || [] } } $self->flat_groups(@_));
}

sub active_entries {
    my $self = shift;
    my $now  = $self->now;
    return (grep {!$_->{'expires'} || $_->{'expires'} ge $now} $self->flat_entries(@_));
}

sub now {
    my ($sec, $min, $hour, $day, $mon, $year) = localtime;
    return sprintf '%04d-%02d-%02d %02d:%02d:%02d', $year+1900, $mon+1, $day, $hour, $min, $sec;
}

sub find_entries {
    my ($self, $args, $groups) = @_;
    my @entries;
    foreach my $g ($self->flat_groups($groups)) {
        foreach my $e (@{ $g->{'entries'} || [] }) {
            next if defined $args->{'group_id'} && (!defined($g->{'id'})       ||  $g->{'id'}       ne $args->{'group_id'});
            next if defined $args->{'title'}    && (!defined($e->{'title'})    ||  $e->{'title'}    ne $args->{'title'});
            next if defined $args->{'username'} && (!defined($e->{'username'}) ||  $e->{'username'} ne $args->{'username'});
            next if defined $args->{'url'}      && (!defined($e->{'url'})      ||  $e->{'url'}      ne $args->{'url'});
            next if defined $args->{'uuid'}     && (!defined($e->{'uuid'})     ||  $e->{'uuid'}     ne $args->{'uuid'});
            push @entries, $e;
        }
    }
    return @entries;
}

sub find_entry {
    my $self = shift;
    my @e = $self->find_entries(@_);
    croak "Found too many entries (@e)" if @e > 1;
    return $e[0];
}

###----------------------------------------------------------------###

sub is_locked {
    my $self = shift;
    my $groups = shift || $self->groups;
    return $locker{"$groups"} ? 1 : 0;
}

sub lock {
    my $self = shift;
    my $groups = shift || $self->groups;
    return 2 if $locker{"$groups"}; # not quite as fast as Scalar::Util::refaddr
    my $ref = $locker{"$groups"} = {};
    foreach my $e ($self->flat_entries($groups)) {
        $ref->{"$e"} = delete $e->{'password'};
    }
    return 1;
}

sub unlock {
    my $self = shift;
    my $groups = shift || $self->groups;
    return 2 if !$locker{"$groups"}; # not quite as fast as Scalar::Util::refaddr
    my $ref = $locker{"$groups"};
    foreach my $e ($self->flat_entries($groups)) {
        $e->{'password'} = $ref->{"$e"};
        $e->{'password'} = '' if ! defined $e->{'password'};
    }
    delete $locker{"$groups"};
    return 1;
}

sub locked_entry_password {
    my $self = shift;
    my $entry = shift;
    my $groups = shift || $self->groups;
    my $ref = $locker{"$groups"} || croak "Passwords aren't locked";
    $entry = $self->find_entry({uuid => $entry}, $groups) if ! ref $entry;
    return if ! $entry;
    my $pass = $ref->{"$entry"};
    return $pass;
}

###----------------------------------------------------------------###

1;

__END__

=head1 SYNOPSIS

=cut
