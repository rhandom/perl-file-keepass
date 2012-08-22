package File::KeePass;

=head1 NAME

File::KeePass - Interface to KeePass V1 database files

=cut

use strict;
use warnings;
use Carp qw(croak);
use Crypt::Rijndael;
use Digest::SHA qw(sha256);

use constant DB_HEADER_SIZE   => 124;
use constant DB_SIG_1         => 0x9AA2D903;
use constant DB_SIG_2_v1      => 0xB54BFB65;
use constant DB_SIG_2_v2      => 0xB54BFB67;
use constant DB_VER_DW        => 0x00030002;
use constant DB_FLAG_SHA2     => 1;
use constant DB_FLAG_RIJNDAEL => 2;
use constant DB_FLAG_ARCFOUR  => 4;
use constant DB_FLAG_TWOFISH  => 8;

our $VERSION = '0.03';
my %locker;
my $salsa20_iv = "\xe8\x30\x09\x4b\x97\x20\x5d\x2a";

sub new {
    my $class = shift;
    my $args  = ref($_[0]) ? {%{shift()}} : {@_};
    return bless $args, $class;
}

sub auto_lock {
    my $self = shift;
    $self->{'auto_lock'} = shift if @_;
    return !exists($self->{'auto_lock'}) || $self->{'auto_lock'};
}

sub groups { shift->{'groups'} || croak "No groups loaded yet\n" }

sub header { shift->{'header'} || croak "No header loaded yet\n" }

sub meta { shift->{'meta'} || croak "No meta information loaded yet\n" }

###----------------------------------------------------------------###

sub load_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";
    my $args = shift || {};

    open my $fh, '<', $file or croak "Could not open $file: $!\n";
    my $size = -s $file;
    read($fh, my $buffer, $size);
    close $fh;
    croak "Could not read entire file contents of $file.\n" if length($buffer) != $size;
    return $self->parse_db($buffer, $pass, $args);
}

sub save_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";
    my $args = shift || {};
    local $args->{'version'} = $args->{'version'}  ? $args->{'version'}
                             : $file =~ /\.kdbx$/i ? 2
                             : $file =~ /\.kdb$/i  ? 1
                             : $self->{'header'}   ? $self->{'header'}->{'header'}
                             : $self->{'version'};

    my $buf = $self->gen_db($pass, $self->groups, $args);
    my $bak = "$file.bak";
    my $tmp = "$file.new.".int(time());
    open my $fh, '>', $tmp or croak "Could not open $tmp: $!\n";
    print $fh $buf;
    close $fh;
    if (-s $tmp ne length($buf)) {
        croak "Written file size of $tmp didn't match (".(-s $tmp)." != ".length($buf).") - not moving into place\n";
        unlink($tmp);
    }

    # try to move the file into place
    if (-e $bak) {
        unlink($bak) or unlink($tmp) or croak "Could not removing already existing backup $bak: $!\n";
    }
    if (-e $file) {
        rename($file, $bak) or unlink($tmp) or croak "Could not backup $file to $bak: $!\n";
    }
    rename($tmp, $file) or croak "Could not move $tmp to $file: $!\n";
    if (!$self->{'keep_backup'} && -e $bak) {
        unlink($bak) or croak "Could not removing temporary backup $bak: $!\n";
    }

    return 1;
}

sub clear {
    my $self = shift;
    $self->unlock;
    delete @$self{qw(header meta groups)};
}

sub DESTROY { shift->clear }

###----------------------------------------------------------------###

sub parse_db {
    my ($self, $buffer, $pass, $args) = @_;
    $self = $self->new($args || {}) if ! ref $self;

    # parse and verify headers
    my $head = $self->parse_header($buffer);
    $buffer = substr $buffer, $head->{'header_size'};

    $self->unlock if $self->{'groups'}; # make sure we don't leave dangling keys should we reopen a new db

    $self->{'header'} = $head;

    my $meth = ($head->{'version'} == 1) ? '_parse_v1_body'
             : ($head->{'version'} == 2) ? '_parse_v2_body'
             : croak "Unsupported keepass database version ($head->{'version'})\n";
    @$self{qw(meta groups)} = $self->$meth($buffer, $pass, $head);

    $self->lock if $self->auto_lock;
    return $self;
}

sub parse_header {
    my ($self, $buffer) = @_;
    my ($sig1, $sig2) = unpack 'LL', $buffer;
    croak "File signature (sig1) did not match ($sig1 != ".DB_SIG_1().")\n" if $sig1 != DB_SIG_1;
    return $self->_parse_v1_header($buffer) if $sig2 eq DB_SIG_2_v1;
    return $self->_parse_v2_header($buffer) if $sig2 eq DB_SIG_2_v2;
    croak "Second file signature did not match ($sig2 != ".DB_SIG_2_v1()." or ".DB_SIG_2_v2().")\n";
}

sub _parse_v1_header {
    my ($self, $buffer) = @_;
    my $size = length($buffer);
    croak "File was smaller than db header ($size < ".DB_HEADER_SIZE().")\n" if $size < DB_HEADER_SIZE;
    my @f = qw(sig1 sig2 flags ver seed_rand enc_iv n_groups n_entries checksum seed_key seed_rot_n);
    my $t =   'L    L    L     L   a16       a16    L        L         a32      a32      L';
    my %h = (version => 1, header_size => DB_HEADER_SIZE);
    @h{@f} = unpack $t, $buffer;
    croak "Unsupported file version ($h{'ver'}).\n" if $h{'ver'} & 0xFFFFFF00 != DB_VER_DW & 0xFFFFFF00;
    $h{'enc_type'} = ($h{'flags'} & DB_FLAG_RIJNDAEL) ? 'rijndael'
                   : ($h{'flags'} & DB_FLAG_TWOFISH)  ? 'twofish'
                   : die "Unknown encryption type\n";
    return \%h;
}

sub _parse_v2_header {
    my ($self, $buffer) = @_;
    my ($sig1, $sig2) = unpack 'LL', $buffer;
    my %h = (sig1 => $sig1, sig2 => $sig2, version => 2, enc_type => 'rijndael');
    my $pos = 8;
    ($h{'ver'}) = unpack "\@$pos L", $buffer;
    $pos += 4;
    croak "Unsupported file version2 ($h{'ver'}).\n" if $h{'ver'} & 0xFFFF0000 > 0x00020000 & 0xFFFF0000;

    while (1) {
        my ($type, $size) = unpack "\@$pos CS", $buffer;
        $pos += 3;
        if (!$type) {
            $pos += $size;
            last;
        }
        my $val = substr $buffer, $pos, $size; # #my ($val) = unpack "\@$pos a$size", $buffer;
        $pos += $size;
        if ($type == 1) {
            $h{'comment'} = $val;
        } elsif ($type == 2) {
            warn "Cipher id did not match AES\n" if $val ne "\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff";
            $h{'cipher'} = 'aes';
        } elsif ($type == 3) {
            $val = unpack 'V', $val;
            warn "Compression was too large.\n" if $val > 1;
            $h{'compression'} = $val;
        } elsif ($type == 4) {
            warn "Length of seed random was not 32\n" if length($val) != 32;
            $h{'seed_rand'} = $val;
        } elsif ($type == 5) {
            warn "Length of seed key was not 32\n" if length($val) != 32;
            $h{'seed_key'} = $val;
        } elsif ($type == 6) {
            $h{'seed_rot_n'} = unpack 'L', $val;
        } elsif ($type == 7) {
            warn "Length of encryption IV was not 16\n" if length($val) != 16;
            $h{'enc_iv'} = $val;
        } elsif ($type == 8) {
            warn "Length of stream key was not 32\n" if length($val) != 32;
            $h{'protected_stream_key'} = $val;
        } elsif ($type == 9) {
            warn "Length of start bytes was not 32\n" if length($val) != 32;
            $h{'start_bytes'} = $val;
        } elsif ($type == 10) {
            warn "Inner stream id did not match Salsa20\n" if unpack('V', $val) != 2;
            $h{'protected_stream'} = 'salsa20';
        } else {
            warn "Found an unknown header type ($type, $val)\n";
        }
    }

    $h{'header_size'} = $pos;
    return \%h;
}

###----------------------------------------------------------------###

sub _master_v1_key {
    my ($self, $pass, $head) = @_;
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);
    return $key;
}

sub _master_v2_key {
    my ($self, $pass, $head) = @_;
    my $key = sha256($pass);
    $key = sha256($key, ()); # this represents the joining of composite data - eventually this would add in File based key as well
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);
    return $key;
}

sub _parse_v1_body {
    my ($self, $buffer, $pass, $head) = @_;

    croak "Unimplemented enc_type $head->{'enc_type'}\n"
        if $head->{'enc_type'} ne 'rijndael';

    my $key = $self->_master_v1_key($pass, $head);
    $buffer = $self->decrypt_rijndael_cbc($buffer, $key, $head->{'enc_iv'});

    croak "The file could not be decrypted either because the key is wrong or the file is damaged.\n"
        if length($buffer) > 2**31 || (!length($buffer) && $head->{'n_groups'});
    croak "The file checksum did not match.\nThe key is wrong or the file is damaged (or we need to implement utf8 input a bit better)\n"
        if $head->{'checksum'} ne sha256($buffer);

    my ($groups, $gmap, $pos) = $self->_parse_v1_groups($buffer, $head->{'n_groups'});
    $self->_parse_v1_entries($buffer, $head->{'n_entries'}, $pos, $gmap, $groups);
    return ({}, $groups);
}

sub _parse_v2_body {
    my ($self, $buffer, $pass, $head) = @_;

    my $key = $self->_master_v2_key($pass, $head);
    $buffer = $self->decrypt_rijndael_cbc($buffer, $key, $head->{'enc_iv'});
    croak "The database key appears invalid or else the database is corrupt.\n"
        if substr($buffer, 0, 32, '') ne $head->{'start_bytes'};

    $buffer = $self->unchunksum($buffer);
    $buffer = $self->decompress($buffer) if ($head->{'compression'} || '') eq '1';
    $self->{'xml'} = $buffer if $self->{'keep_xml'};

    # parse the XML - use our own parser since XML::Simple does not do event based actions
    my $tri = sub { return !defined($_[0]) ? undef : ('true' eq lc $_[0]) ? 1 : ('false' eq lc $_[0]) ? 0 : undef };
    my $s20_stream = $self->salsa20_stream({key => sha256($head->{'protected_stream_key'}), iv => $salsa20_iv, rounds => 20});
    my %BIN;
    my $META;
    my @GROUPS;
    my $level = 0;
    my $data = $self->parse_xml($buffer, {
        top            => 'KeePassFile',
        force_array    => {map {$_ => 1} qw(Binaries Binary Group Entry String Association)},
        start_handlers => {Group => sub { $level++ }},
        end_handlers   => {
            Meta => sub {
                my ($node, $parent) = @_;
                croak "Found multiple intances of Meta.\n" if $META;
                $META = {};
                for my $key (keys %$node) {
                    next if $key eq 'Binaries';
                    (my $copy = $key) =~ s/([a-z])([A-Z])/${1}_${2}/g;
                    $META->{lc $copy} = $copy =~ /_changed$/i ? $self->_parse_v2_date($node->{$key}) : $node->{$key};
                }
                $META->{'recycle_bin_enabled'} = $tri->($META->{'recycle_bin_enabled'});
            },
            Binary => sub {
                my ($node, $parent, $parent_tag, $tag) = @_;
                if ($parent_tag eq 'Binaries') {
                    my ($content, $id, $comp) = @$node{qw(content ID Compressed)};
                    $content = $self->decode_base64($content); # I think some binaries can also be protected
                    if ($comp && $comp eq 'True') {
                        eval { $content = $self->decompress($content) } or warn "Could not decompress associated binary ($id): $@";
                    }
                    warn "Duplicate binary id $id - using most recent.\n" if exists $BIN{$id};
                    $BIN{$id} = $content;
                } elsif ($parent_tag eq 'Entry') {
                    my $key = $node->{'Key'};
                    $key = do { warn "Missing key for binary."; 'unknown' } if ! defined $key;
                    warn "Duplicate binary key for entry." if $parent->{'__binary__'}->{$key};
                    $parent->{'__binary__'}->{$key} = $BIN{$node->{'Value'}->{'Ref'}};
                }
            },
            MemoryProtection => sub {
                my $node = shift;
                for my $key (keys %$node) {
                    $node->{lc $1} = delete($node->{$key}) eq 'True' ? 1 : 0 if $key =~ /^Protect(\w+)$/;
                }
            },
            Group => sub {
                my ($node, $parent, $parent_tag) = @_;
                my $group = {
                    id       => $node->{'UUID'},
                    icon     => $node->{'IconID'},
                    title    => $node->{'Name'},
                    expanded => $tri->($node->{'IsExpanded'}),
                    level    => $level,
                    accessed => $self->_parse_v2_date($node->{'Times'}->{'LastAccessTime'}),
                    expires  => $self->_parse_v2_date($node->{'Times'}->{'ExpiryTime'}),
                    created  => $self->_parse_v2_date($node->{'Times'}->{'CreationTime'}),
                    modified => $self->_parse_v2_date($node->{'Times'}->{'LastModificationTime'}),
                    v2_extra => {
                        default_auto_type => $node->{'DefaultAutoTypeSequence'},
                        enable_auto_type  => $tri->($node->{'EnableAutoType'}),
                        enable_searching  => $tri->($node->{'EnableSearching'}),
                        last_top_entry    => $node->{'LastTopVisibleEntry'},
                        custom_icon_uuid  => $node->{'CustomIconUUID'},
                        expires           => $tri->($node->{'Expires'}),
                        location_changed  => $self->_parse_v2_date($node->{'Times'}->{'LocationChanged'}),
                        usage_count       => $node->{'Times'}->{'UsageCount'},
                        notes             => $node->{'Notes'},
                    },
                    entries => delete($node->{'__entries__'}) || [],
                    groups  => delete($node->{'__groups__'})  || [],
                };
                $group->{'v2_raw'} = $node if $self->{'keep_xml'};
                if ($parent_tag eq 'Group') {
                    push @{ $parent->{'__groups__'} }, $group;
                } else {
                    $group->{'__parent_tag__'} = $parent_tag;
                    push @GROUPS, $group;
                }
            },
            Entry => sub {
                my ($node, $parent, $parent_tag) = @_;
                my %str = map {$_->{'Key'} => $_->{'Value'}} @{ $node->{'String'} || [] };
                my $entry = {
                    accessed => $self->_parse_v2_date($node->{'Times'}->{'LastAccessTime'}),
                    created  => $self->_parse_v2_date($node->{'Times'}->{'CreationTime'}),
                    expires  => $self->_parse_v2_date($node->{'Times'}->{'ExpiryTime'}),
                    modified => $self->_parse_v2_date($node->{'Times'}->{'LastModificationTime'}),
                    comment  => delete($str{'Notes'}),
                    icon     => $node->{'IconID'},
                    id       => $node->{'UUID'},
                    title    => delete($str{'Title'}),
                    url      => delete($str{'URL'}),
                    username => delete($str{'UserName'}),
                    password => delete($str{'Password'}),
                    v2_extra => {
                        expires           => $tri->($node->{'Expires'}),
                        location_changed  => $self->_parse_v2_date($node->{'Times'}->{'LocationChanged'}),
                        usage_count       => $node->{'Times'}->{'UsageCount'},
                        tags              => $node->{'Tags'},
                        background_color  => $node->{'BackgroundColor'},
                        foreground_color  => $node->{'ForegroundColor'},
                        custom_icon_uuid  => $node->{'CustomIconUUID'},
                        history           => $node->{'History'},
                        override_url      => $node->{'OverrideURL'},
                        auto_type         => $node->{'AutoType'},
                    },
                };
                $entry->{'v2_extra'}->{'strings'} = \%str if scalar keys %str;
                $entry->{'binary'} = delete($node->{'__binary__'}) if $node->{'__binary__'};
                $entry->{'v2_raw'} = $node if $self->{'keep_xml'};
                push @{ $parent->{'__entries__'} }, $entry;
            },
            String => sub {
                my $node = shift;
                my $val = $node->{'Value'};
                if (ref($val) eq 'HASH' && $val->{'Protected'} && $val->{'Protected'} eq 'True') {
                    $val = $val->{'content'};
                    $node->{'Value'} = length($val) ? $s20_stream->($self->decode_base64($val)) : '';
                }
            },
            History => sub {
                my ($node, $parent, $parent_tag, $tag) = @_;
                $parent->{$tag} = delete($node->{'__entries__'});
            },
        },
    });

    return ($META, \@GROUPS);
}

###----------------------------------------------------------------###

sub _parse_v1_groups {
    my ($self, $buffer, $n_groups) = @_;
    my $pos = 0;

    my @groups;
    my %gmap; # allow entries to find their groups (group map)
    my @gref = (\@groups); # group ref pointer stack - let levels nest safely
    my $group = {};
    while ($n_groups) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Group header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Group header offset is out of range. ($pos, $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $group->{'id'}       = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 2) {
            ($group->{'title'}   = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 3) {
            $group->{'created'}  = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 4) {
            $group->{'modified'} = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 5) {
            $group->{'accessed'} = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 6) {
            $group->{'expires'}  = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 7) {
            $group->{'icon'}     = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 8) {
            $group->{'level'}    = unpack 'S', substr($buffer, $pos, 2);
        } elsif ($type == 0xFFFF) {
            $group->{'created'} ||= '';
            $n_groups--;
            $gmap{$group->{'id'}} = $group;
            my $level = $group->{'level'} || 0;
            if (@gref > $level + 1) { # gref is index base 1 because the root is a pointer to \@groups
                splice @gref, $level + 1;
            } elsif (@gref < $level + 1) {
                push @gref, ($gref[-1]->[-1]->{'groups'} = []);
            }
            push @{ $gref[-1] }, $group;
            $group = {};
        } else {
            $group->{'unknown'}->{$type} = substr($buffer, $pos, $size);
        }
        $pos += $size;
    }

    return (\@groups, \%gmap, $pos);
}

sub _parse_v1_entries {
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
            $entry->{'id'}        = unpack 'H*', substr($buffer, $pos, $size);
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
            $entry->{'created'}   = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xA) {
            $entry->{'modified'}  = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xB) {
            $entry->{'accessed'}  = $self->_parse_v1_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xC) {
            $entry->{'expires'}   = $self->_parse_v1_date(substr($buffer, $pos, $size));
	} elsif ($type == 0xD) {
            ($entry->{'bin_desc'} = substr($buffer, $pos, $size)) =~ s/\0$//;
	} elsif ($type == 0xE) {
            $entry->{'binary'}    = substr($buffer, $pos, $size);
        } elsif ($type == 0xFFFF) {
            $entry->{'created'} ||= '';
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

sub _parse_v1_date {
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

sub _parse_v2_date {
    my ($self, $date) = @_;
    return ($date && $date =~ /^(\d\d\d\d-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)Z?$/) ? "$1 $2" : '';
}

###----------------------------------------------------------------###

sub decrypt_rijndael_cbc {
    my ($self, $buffer, $key, $enc_iv) = @_;
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    $buffer = $cipher->decrypt($buffer);
    my $extra = ord(substr $buffer, -1, 1);
    substr($buffer, length($buffer) - $extra, $extra, '');
    return $buffer;
}

sub encrypt_rijndael_cbc {
    my ($self, $buffer, $key, $enc_iv) = @_;
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    my $extra = (16 - length($buffer) % 16) || 16; # always pad so we can always trim
    $buffer .= chr($extra) for 1 .. $extra;
    return $cipher->encrypt($buffer);
}

sub unchunksum {
    my ($self, $buffer) = @_;
    my ($new, $pos) = ('', 0);
    while ($pos < length($buffer)) {
        my ($index, $hash, $size) = unpack "\@$pos L a32 i", $buffer;
        $pos += 40;
        if ($size == 0) {
            warn "Found mismatch for 0 chunksize\n" if $hash !~ /^\x00{32}$/;
            last;
        }
        my $chunk = substr $buffer, $pos, $size;
        croak "Chunk hash of index $index did not match\n" if $hash ne sha256($chunk);
        $pos += $size;
        $new .= $chunk;
    }
    return $new;
}

sub decompress {
    my ($self, $buffer) = @_;
    eval { require Compress::Zlib } or croak "Cannot load compression library to decompress database: $@";
    my ($i, $status) = Compress::Zlib::inflateInit(-WindowBits => 31);
    croak "Failed to initialize inflator ($status)\n" if $status != Compress::Zlib::Z_OK();
    ($buffer, $status) = $i->inflate($buffer);
    croak "Failed to uncompress buffer ($status)\n" if $status != Compress::Zlib::Z_STREAM_END();
    return $buffer;
}

sub decode_base64 {
    my ($self, $content) = @_;
    eval { require MIME::Base64 } or croak "Cannot load Base64 library to decode item: $@";
    return MIME::Base64::decode_base64($content);
}

sub parse_xml {
    my ($self, $buffer, $args) = @_;
    eval { require XML::Parser } or croak "Cannot load XML library to parse database: $@";
    my $top = $args->{'top'};
    my $force_array = $args->{'force_array'} || {};
    my $s_handlers  = $args->{'start_handlers'} || {};
    my $e_handlers  = $args->{'end_handlers'}   || $args->{'handlers'} || {};
    my $data;
    my $ptr;
    my $x = XML::Parser->new(Handlers => {
        Start => sub {
            my ($x, $tag, %attr) = @_; # loses multiple values of duplicately named attrs
            my $prev_ptr = $ptr;
            $top = $tag if !defined $top;
            if ($tag eq $top) {
                croak "The $top tag should only be used at the top level.\n" if $ptr || $data;
                $ptr = $data = {};
            } elsif (exists($prev_ptr->{$tag})  || ($force_array->{$tag} and $prev_ptr->{$tag} ||= [])) {
                $prev_ptr->{$tag} = [$prev_ptr->{$tag}] if 'ARRAY' ne ref $prev_ptr->{$tag};
                push @{ $prev_ptr->{$tag} }, ($ptr = {});
            } else {
                $ptr = $prev_ptr->{$tag} ||= {};
            }
            @$ptr{keys %attr} = values %attr;
            $_->($ptr, $prev_ptr, $prev_ptr->{'__tag__'}, $tag) if $_ = $s_handlers->{$tag} || $s_handlers->{'__any__'};
            @$ptr{qw(__parent__ __tag__)} = ($prev_ptr, $tag);
        },
        End => sub {
            my ($x, $tag) = @_;
            my $cur_ptr = $ptr;
            $ptr = delete $cur_ptr->{'__parent__'};
            die "End tag mismatch on $tag.\n" if $tag ne delete($cur_ptr->{'__tag__'});
            my $n_keys = scalar keys %$cur_ptr;
            if (!$n_keys) {
                $ptr->{$tag} = ''; # SuppressEmpty
            } elsif (exists $cur_ptr->{'content'}) {
                if ($n_keys == 1) {
                    if ($ptr->{$tag} eq 'ARRAY') {
                        $ptr->{$tag}->[-1] = $cur_ptr->{'content'};
                    } else {
                        $ptr->{$tag} = $cur_ptr->{'content'};
                    }
                } elsif ($cur_ptr->{'content'} !~ /\S/) {
                    delete $cur_ptr->{'content'};
                }
            }
            $_->($cur_ptr, $ptr, $ptr->{'__tag__'}, $tag) if $_ = $e_handlers->{$tag} || $e_handlers->{'__any__'};
        },
        Char => sub { if (defined $ptr->{'content'}) { $ptr->{'content'} .= $_[1] } else { $ptr->{'content'} = $_[1] } },
    });
    $x->parse($buffer);
    return $data;
}

###----------------------------------------------------------------###

sub gen_db {
    my ($self, $pass, $groups, $head, $meta) = @_;
    $groups ||= $self->groups;
    $head   ||= {};
    $meta   ||= $self->meta;
    croak "Missing pass\n" if ! defined($pass);
    croak "Please unlock before calling gen_db" if $self->is_locked($groups);

    srand((time() ^ $$) * rand()) if ! $self->{'srand'};
    foreach my $key (qw(seed_rand enc_iv)) {
        next if defined $head->{$key};
        $head->{$key} = '';
        $head->{$key} .= chr(int(255 * rand())) for 1..16;
    }
    $head->{'seed_key'}   = sha256(time.rand().$$) if ! defined $head->{'seed_key'};
    $head->{'seed_rot_n'} = 50_000 if ! defined $head->{'seed_rot_n'};
    $head->{'sig1'}       = DB_SIG_1();
    $head->{'sig2'}       = DB_SIG_2_v1();

    if (($head->{'version'} || $self->{'version'} || '') eq '2') {
        return $self->_gen_v2_db($pass, $groups, $head, $meta);
    } else {
        return $self->_gen_v1_db($pass, $groups, $head, $meta);
    }
}

sub _gen_v1_db {
    my ($self, $pass, $groups, $head, $meta) = @_;

    my $key = $self->_master_v1_key($pass, $head);

    my $buffer  = '';
    my $entries = '';
    my @g = $self->find_groups({}, $groups);
    if (grep {$_->{'expanded'}} @g) {
        my $e = ($self->find_entries({title => 'Meta-Info', username => 'SYSTEM', comment => 'KPX_GROUP_TREE_STATE', url => '$'}))[0] || $self->add_entry({
            comment  => 'KPX_GROUP_TREE_STATE',
            title    => 'Meta-Info',
            username => 'SYSTEM',
            url      => '$',
            id     => '00000000000000000000000000000000',
            group    => $g[0],
        });
        $e->{'bin_desc'} = 'bin-stream';
        $e->{'binary'} = pack 'L', scalar(@g);
        $e->{'binary'} .= pack('LC', $_->{'id'}, $_->{'expanded'} ? 1 : 0) for @g;
    }
    foreach my $g (@g) {
        $head->{'n_groups'}++;
        my @d = ([1,      pack('LL', 4, $g->{'id'})],
                 [2,      pack('L', length($g->{'title'})+1)."$g->{'title'}\0"],
                 [3,      pack('L',  5). $self->_gen_v1_date($g->{'created'}  || $self->now)],
                 [4,      pack('L',  5). $self->_gen_v1_date($g->{'modified'} || $self->now)],
                 [5,      pack('L',  5). $self->_gen_v1_date($g->{'accessed'} || $self->now)],
                 [6,      pack('L',  5). $self->_gen_v1_date($g->{'expires'}  || $self->default_exp)],
                 [7,      pack('LL', 4, $g->{'icon'}  || 0)],
                 [8,      pack('LS', 2, $g->{'level'} || 0)],
                 [0xFFFF, pack('L', 0)]);
        push @d, [$_, $g->{'unknown'}->{$_}] for keys %{ $g->{'unknown'} || {} };
        $buffer .= pack('S',$_->[0]).$_->[1] for sort {$a->[0] <=> $b->[0]} @d;
        foreach my $e (@{ $g->{'entries'} || [] }) {
            $head->{'n_entries'}++;
            my @d = ([1,      pack('LH*', length($e->{'id'})/2, $e->{'id'})],
                     [2,      pack('LL', 4, $g->{'id'}   || 0)],
                     [3,      pack('LL', 4, $e->{'icon'} || 0)],
                     [4,      pack('L', length($e->{'title'})+1)."$e->{'title'}\0"],
                     [5,      pack('L', length($e->{'url'})+1).   "$e->{'url'}\0"],
                     [6,      pack('L', length($e->{'username'})+1). "$e->{'username'}\0"],
                     [7,      pack('L', length($e->{'password'})+1). "$e->{'password'}\0"],
                     [8,      pack('L', length($e->{'comment'})+1).  "$e->{'comment'}\0"],
                     [9,      pack('L', 5). $self->_gen_v1_date($e->{'created'}  || $self->now)],
                     [0xA,    pack('L', 5). $self->_gen_v1_date($e->{'modified'} || $self->now)],
                     [0xB,    pack('L', 5). $self->_gen_v1_date($e->{'accessed'} || $self->now)],
                     [0xC,    pack('L', 5). $self->_gen_v1_date($e->{'expires'}  || $self->default_exp)],
                     [0xD,    pack('L', length($e->{'bin_desc'})+1)."$e->{'bin_desc'}\0"],
                     [0xE,    pack('L', length($e->{'binary'})).$e->{'binary'}],
                     [0xFFFF, pack('L', 0)]);
            push @d, [$_, $e->{'unknown'}->{$_}] for keys %{ $e->{'unknown'} || {} };
            $entries .= pack('S',$_->[0]).$_->[1] for sort {$a->[0] <=> $b->[0]} @d;
        }
    }
    $buffer .= $entries; $entries = '';

    $head->{'checksum'} = sha256($buffer);
    $head->{'flags'} = DB_FLAG_RIJNDAEL();
    $head->{'ver'}   = DB_VER_DW();

    return $self->_gen_v1_header($head) . $self->encrypt_rijndael_cbc($buffer, $key, $head->{'enc_iv'});
}

sub _gen_v1_header {
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

sub _gen_v1_date {
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

sub _gen_v2_db {
    my ($self, $pass, $groups, $head, $meta) = @_;

    my $key = $self->_master_v1_key($pass, $head);

    my $buffer  = '';
    croak "Not implemented\n";
}

###----------------------------------------------------------------###

sub dump_groups {
    my ($self, $args, $groups) = @_;
    my $t = '';
    my %gargs; for (keys %$args) { $gargs{$2} = $args->{$1} if /^(group_(.+))$/ };
    foreach my $g ($self->find_groups(\%gargs, $groups)) {
        my $indent = '    ' x $g->{'level'};
        $t .= $indent.($g->{'expanded'} ? '-' : '+')."  $g->{'title'} ($g->{'id'}) $g->{'created'}\n";
        local $g->{'groups'}; # don't recurse while looking for entries since we are already flat
        $t .= "$indent    > $_->{'title'}\t($_->{'id'}) $_->{'created'}\n" for $self->find_entries($args, [$g]);
    }
    return $t;
}

sub add_group {
    my ($self, $args, $top_groups) = @_;
    $args = {%$args};
    my $groups;
    my $parent_group = delete $args->{'group'};
    if (defined $parent_group) {
        $parent_group = $self->find_group({id => $parent_group}, $top_groups) if ! ref($parent_group);
        $groups = $parent_group->{'groups'} ||= [] if $parent_group;
    }
    $groups ||= $top_groups || ($self->{'groups'} ||= []);

    $args->{$_} = $self->now for grep {!defined $args->{$_}} qw(created accessed modified);;
    $args->{'expires'} ||= $self->default_exp;

    push @$groups, $args;
    $self->find_groups({}, $groups); # sets title, level, icon and id
    return $args;
}

sub finder_tests {
    my ($self, $args) = @_;
    my @tests;
    foreach my $key (keys %{ $args || {} }) {
        next if ! defined $args->{$key};
        my ($field, $op) = ($key =~ m{ ^ (\w+) \s* (|!|=|!~|=~|gt|lt) $ }x) ? ($1, $2) : croak "Invalid find match criteria \"$key\"";
        push @tests,  (!$op || $op eq '=') ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} eq $args->{$key} }
                    : ($op eq '!')         ? sub { !defined($_[0]->{$field}) || $_[0]->{$field} ne $args->{$key} }
                    : ($op eq '=~')        ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} =~ $args->{$key} }
                    : ($op eq '!~')        ? sub { !defined($_[0]->{$field}) || $_[0]->{$field} !~ $args->{$key} }
                    : ($op eq 'gt')        ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} gt $args->{$key} }
                    : ($op eq 'lt')        ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} lt $args->{$key} }
                    : croak;
    }
    return @tests;
}

sub find_groups {
    my ($self, $args, $groups, $level) = @_;
    my @tests = $self->finder_tests($args);
    my @groups;
    my %used;
    my $container = $groups || $self->groups;
    for my $g (@$container) {
        $g->{'level'} = $level || 0;
        $g->{'title'} = '' if ! defined $g->{'title'};
        $g->{'icon'}  ||= 0;
        while (!defined($g->{'id'}) || $used{$g->{'id'}}++) {
            warn "Found duplicate group_id - generating new one for \"$g->{'title'}\"" if defined($g->{'id'});
            $g->{'id'} = int((2**32-1) * rand());
        }
        if (!@tests || !grep{!$_->($g)} @tests) {
            push @groups, $g;
            push @{ $self->{'__group_groups'} }, $container if $self->{'__group_groups'};
        }
        push @groups, $self->find_groups($args, $g->{'groups'}, $g->{'level'} + 1) if $g->{'groups'};
    }
    return @groups;
}

sub find_group {
    my $self = shift;
    local $self->{'__group_groups'} = [] if wantarray;
    my @g = $self->find_groups(@_);
    croak "Found too many groups (@g)" if @g > 1;
    return wantarray ? ($g[0], $self->{'__group_groups'}->[0]) : $g[0];
}

sub delete_group {
    my $self = shift;
    my ($g, $c) = $self->find_group(@_);
    return if !$g || !$c;
    for my $i (0 .. $#$c) {
        next if $c->[$i] ne $g;
        splice(@$c, $i, 1, ());
        last;
    }
    return $g;
}

###----------------------------------------------------------------###

sub add_entry {
    my ($self, $args, $groups) = @_;
    $groups ||= $self->groups;
    croak "You must unlock the passwords before adding new entries.\n" if $self->is_locked($groups);
    $args = {%$args};
    my $group = delete($args->{'group'}) || $groups->[0] || $self->add_group({});
    if (! ref($group)) {
        $group = $self->find_group({id => $group}, $groups) || croak "Could not find a matching group to add entry to";
    }

    $args->{$_} = ''         for grep {!defined $args->{$_}} qw(title url username password comment bin_desc binary);
    $args->{$_} = 0          for grep {!defined $args->{$_}} qw(id icon);
    $args->{$_} = $self->now for grep {!defined $args->{$_}} qw(created accessed modified);
    $args->{'expires'} ||= $self->default_exp;
    while (!$args->{'id'} || $args->{'id'} !~ /^[a-f0-9]{32}$/ || $self->find_entry({id => $args->{'id'}}, $groups)) {
        $args->{'id'} = unpack 'H32', sha256(time.rand().$$);
    }

    push @{ $group->{'entries'} ||= [] }, $args;
    return $args;
}

sub find_entries {
    my ($self, $args, $groups) = @_;
    local @{ $args }{'expires gt', 'active'} = ($self->now, undef) if $args->{'active'};
    my @tests = $self->finder_tests($args);
    my @entries;
    foreach my $g ($self->find_groups({}, $groups)) {
        foreach my $e (@{ $g->{'entries'} || [] }) {
            local $e->{'group_id'}    = $g->{'id'};
            local $e->{'group_title'} = $g->{'title'};
            if (!@tests || !grep{!$_->($e)} @tests) {
                push @entries, $e;
                push @{ $self->{'__entry_groups'} }, $g if $self->{'__entry_groups'};
            }
        }
    }
    return @entries;
}

sub find_entry {
    my $self = shift;
    local $self->{'__entry_groups'} = [] if wantarray;
    my @e = $self->find_entries(@_);
    croak "Found too many entries (@e)" if @e > 1;
    return wantarray ? ($e[0], $self->{'__entry_groups'}->[0]) : $e[0];
}

sub delete_entry {
    my $self = shift;
    my ($e, $g) = $self->find_entry(@_);
    return if !$e || !$g;
    for my $i (0 .. $#{ $g->{'entries'} || [] }) {
        next if $g->{'entries'}->[$i] ne $e;
        splice(@{ $g->{'entries'} }, $i, 1, ());
        last;
    }
    return $e;
}

sub now {
    my ($sec, $min, $hour, $day, $mon, $year) = localtime;
    return sprintf '%04d-%02d-%02d %02d:%02d:%02d', $year+1900, $mon+1, $day, $hour, $min, $sec;
}

sub default_exp { shift->{'default_exp'} || '2999-12-31 23:23:59' }

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
    foreach my $key (qw(_key _enc_iv)) {
        $ref->{$key} = '';
        $ref->{$key} .= chr(int(255 * rand())) for 1..16;
    }

    foreach my $e ($self->find_entries({}, $groups)) {
        my $pass = delete $e->{'password'}; $pass = '' if ! defined $pass;
        $ref->{"$e"} = $self->encrypt_rijndael_cbc($pass, $ref->{'_key'}, $ref->{'_enc_iv'}); # we don't leave plaintext in memory
    }

    return 1;
}

sub unlock {
    my $self = shift;
    my $groups = shift || $self->groups;
    return 2 if !$locker{"$groups"};
    my $ref = $locker{"$groups"};
    foreach my $e ($self->find_entries({}, $groups)) {
        my $pass = $ref->{"$e"};
        $pass = eval { $self->decrypt_rijndael_cbc($pass, $ref->{'_key'}, $ref->{'_enc_iv'}) } if $pass;
        $pass = '' if ! defined $pass;
        $e->{'password'} = $pass;
    }
    delete $locker{"$groups"};
    return 1;
}

sub locked_entry_password {
    my $self = shift;
    my $entry = shift;
    my $groups = shift || $self->groups;
    my $ref = $locker{"$groups"} || croak "Passwords aren't locked";
    $entry = $self->find_entry({id => $entry}, $groups) if ! ref $entry;
    return if ! $entry;
    my $pass = $ref->{"$entry"};
    $pass = eval { $self->decrypt_rijndael_cbc($pass, $ref->{'_key'}, $ref->{'_enc_iv'}) } if $pass;
    $pass = '' if ! defined $pass;
    $entry->{'accessed'} = $self->now;
    return $pass;
}

###----------------------------------------------------------------###

sub salsa20_stream {
    my ($self, $args) = @_;
    delete $args->{'data'};
    my $salsa20 = $self->salsa20($args);
    my $buffer = '';
    return sub {
        my $enc = shift;
        $buffer .= $salsa20->("\0" x 64) while length($buffer) < length($enc);
        my $data = join '', map {chr(ord(substr $enc, $_, 1) ^ ord(substr $buffer, $_, 1))} 0 .. length($enc)-1;
        substr $buffer, 0, length($enc), '';
        return $data;
    };
}


sub salsa20 { # http://cr.yp.to/snuffle/salsa20/regs/salsa20.c
    my ($self, $args) = @_;
    my ($key, $iv, $rounds) = @$args{qw(key iv rounds)};
    $rounds ||= 20;

    my (@k, @c);
    if (32 == length $key) {
        @k = unpack 'L8', $key;
        @c = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574); # SIGMA
    } elsif (16 == length $key) {
        @k = unpack 'L8', $key x 2;
        @c = (0x61707865, 0x3120646e, 0x79622d36, 0x6b206574); # TAU
    } else {
        die "Salsa20 key length must be 16 or 32\n";
    }
    die "Salsa20 IV length must be 8\n" if length($iv) != 8;
    die "Salsa20 rounds must be 8, 12, or 20.\n" if !grep {$rounds != $_} 8, 12, 20;
    my @v = unpack('L2', $iv);

    #            0                                  5      6      7            10                                 # 15
    my @state = ($c[0], $k[0], $k[1], $k[2], $k[3], $c[1], $v[0], $v[1], 0, 0, $c[2], $k[4], $k[5], $k[6], $k[7], $c[3]);

    my $rotl32 = sub { return (($_[0] << $_[1]) | ($_[0] >> (32 - $_[1]))) & 0xffffffff };
    my $word_to_byte = sub {
        my @x = @state;
        for (1 .. $rounds/2) {
            $x[ 4] ^= $rotl32->(($x[ 0] + $x[12]) & 0xffffffff,  7);
            $x[ 8] ^= $rotl32->(($x[ 4] + $x[ 0]) & 0xffffffff,  9);
            $x[12] ^= $rotl32->(($x[ 8] + $x[ 4]) & 0xffffffff, 13);
            $x[ 0] ^= $rotl32->(($x[12] + $x[ 8]) & 0xffffffff, 18);
            $x[ 9] ^= $rotl32->(($x[ 5] + $x[ 1]) & 0xffffffff,  7);
            $x[13] ^= $rotl32->(($x[ 9] + $x[ 5]) & 0xffffffff,  9);
            $x[ 1] ^= $rotl32->(($x[13] + $x[ 9]) & 0xffffffff, 13);
            $x[ 5] ^= $rotl32->(($x[ 1] + $x[13]) & 0xffffffff, 18);
            $x[14] ^= $rotl32->(($x[10] + $x[ 6]) & 0xffffffff,  7);
            $x[ 2] ^= $rotl32->(($x[14] + $x[10]) & 0xffffffff,  9);
            $x[ 6] ^= $rotl32->(($x[ 2] + $x[14]) & 0xffffffff, 13);
            $x[10] ^= $rotl32->(($x[ 6] + $x[ 2]) & 0xffffffff, 18);
            $x[ 3] ^= $rotl32->(($x[15] + $x[11]) & 0xffffffff,  7);
            $x[ 7] ^= $rotl32->(($x[ 3] + $x[15]) & 0xffffffff,  9);
            $x[11] ^= $rotl32->(($x[ 7] + $x[ 3]) & 0xffffffff, 13);
            $x[15] ^= $rotl32->(($x[11] + $x[ 7]) & 0xffffffff, 18);

            $x[ 1] ^= $rotl32->(($x[ 0] + $x[ 3]) & 0xffffffff,  7);
            $x[ 2] ^= $rotl32->(($x[ 1] + $x[ 0]) & 0xffffffff,  9);
            $x[ 3] ^= $rotl32->(($x[ 2] + $x[ 1]) & 0xffffffff, 13);
            $x[ 0] ^= $rotl32->(($x[ 3] + $x[ 2]) & 0xffffffff, 18);
            $x[ 6] ^= $rotl32->(($x[ 5] + $x[ 4]) & 0xffffffff,  7);
            $x[ 7] ^= $rotl32->(($x[ 6] + $x[ 5]) & 0xffffffff,  9);
            $x[ 4] ^= $rotl32->(($x[ 7] + $x[ 6]) & 0xffffffff, 13);
            $x[ 5] ^= $rotl32->(($x[ 4] + $x[ 7]) & 0xffffffff, 18);
            $x[11] ^= $rotl32->(($x[10] + $x[ 9]) & 0xffffffff,  7);
            $x[ 8] ^= $rotl32->(($x[11] + $x[10]) & 0xffffffff,  9);
            $x[ 9] ^= $rotl32->(($x[ 8] + $x[11]) & 0xffffffff, 13);
            $x[10] ^= $rotl32->(($x[ 9] + $x[ 8]) & 0xffffffff, 18);
            $x[12] ^= $rotl32->(($x[15] + $x[14]) & 0xffffffff,  7);
            $x[13] ^= $rotl32->(($x[12] + $x[15]) & 0xffffffff,  9);
            $x[14] ^= $rotl32->(($x[13] + $x[12]) & 0xffffffff, 13);
            $x[15] ^= $rotl32->(($x[14] + $x[13]) & 0xffffffff, 18);
        }
        return pack 'L16', map {($x[$_] + $state[$_]) & 0xffffffff} 0 .. 15;
    };

    my $encoder = sub {
        my $enc = shift;
        my $out = '';
        while (length $enc) {
            my $stream = $word_to_byte->();
            $state[8] = ($state[8] + 1) & 0xffffffff;
            $state[9] = ($state[9] + 1) & 0xffffffff if $state[8] == 0;
            my $chunk = substr $enc, 0, 64, '';
            $out .= join '', map {chr(ord(substr $stream, $_, 1) ^ ord(substr $chunk, $_, 1))} 0 .. length($chunk)-1;
        }
        return $out;
    };
    return $encoder if !exists $args->{'data'};
    return $encoder->(defined($args->{'data'}) ? $args->{'data'} : '');
}

###----------------------------------------------------------------###

1;

__END__

=head1 SYNOPSIS

    use File::KeePass;


    my $k = File::KeePass->new;

    # read a version 1 or version 2 database
    $k->load_db($file, $master_pass); # errors die

    use Data::Dumper qw(Dumper);
    print Dumper $k->groups; # passwords are locked

    $k->unlock;
    print Dumper $k->groups; # passwords are now visible

    $k->clear; # delete current db from memory


    my $group = $k->add_group({
        title => 'Foo',
    }); # root level group
    my $gid = $group->{'id'};

    my $group = $k->find_group({id => $gid});
    # OR
    my $group = $k->find_group({title => 'Foo'});


    my $group2 = $k->add_group({
        title => 'Bar',
        group => $gid,
        # OR group => $group,
    }); # nested group


    my $e = $k->add_entry({
        title    => 'Something',
        username => 'someuser',
        password => 'somepass',
        group    => $gid,
        # OR group => $group,
    });
    my $eid = $e->{'id'};

    my $e = $k->find_entry({id => $eid});
    # OR
    my $e = $k->find_entry({title => 'Something'});

    $k->lock;
    print $e->{'password'}; # eq undef
    print $k->locked_entry_password($e); # eq 'somepass'

    $k->unlock;
    print $e->{'password'}; # eq 'somepass'


    # save out a version 1 database
    $k->save_db("/some/file/location.kdb", $master_pass);

    # save out a version 2 database
    $k->save_db("/some/file/location.kdbx", $master_pass);

=head1 DESCRIPTION

File::KeePass gives access to KeePass version 1 (kdb) and
version 2 (kdbx) databases.


The version 1 and version 2 databases are very different in
construction, but the majority of information overlaps.  File::KeePass
attempts to iron out as many of the differences.

=head1 METHODS

=over 4

=item new

Takes a hashref or hash of arguments.  Returns a new File::KeePass
object.  Any named arguments are added to self.

=item load_db

Takes a kdb filename, a master password, and an optional argument
hashref.  Returns the File::KeePass object on success (can be called
as a class method).  Errors die.  The resulting database can be
accessed via various methods including $k->groups.

    my $k = File::KeePass->new;
    $k->load_db($file, $pwd);

    my $k = File::KeePass->load_db($file, $pwd);

    my $k = File::KeePass->load_db($file, $pwd, {auto_lock => 0});

The contents are read from file and passed to parse_db.

=item save_db

Takes a kdb filename and a master password.  Stores out the current
groups in the object.  Writes attempt to write first to
$file.new.$epoch and are then renamed into the correct location.

You will need to unlock the db via $k->unlock before calling this
method if the database is currently locked.

=item parse_db

Takes an string containting an encrypted kdb database, a master
password, and an optional argument hashref.  Returns the File::KeePass
object on success (can be called as a class method).  Errors die.  The
resulting database can be accessed via various methods including
$k->groups.

    my $k = File::KeePass->new;
    $k->parse_db($loaded_kdb, $pwd);

    my $k = File::KeePass->parse_db($kdb_buffer, $pwd);

    my $k = File::KeePass->parse_db($kdb_buffer, $pwd, {auto_lock => 0});

=item parse_header

Used by parse_db.  Reads just the header information.  Can be used as
a basic KeePass file check.  The returned hash will contain version =>
1 or version => 2 depending upon which type of header is found.  Can
be called as a class method.

    my $head = File::KeePass->parse_header($kdb_buffer); # errors die
    printf "This is a version %d database\n", $head->{'version'};

=item gen_db

Takes a master password.  Optionally takes a "groups" arrayref and a
"headers" hashref.  If groups are not passed, it defaults to using the
currently loaded groups.  If headers are not passed, a fresh set of
headers are generated based on the groups and the master password.
The headers can be passed in to test round trip portability.

You will need to unlock the db via $k->unlock before calling this
method if the database is currently locked.

=item clear

Clears any currently loaded database.

=item auto_lock

Default true.  If true, passwords are automatically hidden when a
database loaded via parse_db or load_db.

    $k->auto_lock(0); # turn off auto locking

=item is_locked

Returns true if the current database is locked.

=item lock

Locks the database.  This moves all passwords into a protected, in
memory, encrypted storage location.  Returns 1 on success.  Returns 2
if the db is already locked.  If a database is loaded via parse_db or
load_db and auto_lock is true, the newly loaded database will start
out locked.

=item unlock

Unlocks a previously locked database.  You will need to unlock a
database before calling save_db or gen_db.

=back

=head1 GROUP/ENTRY METHODS

=over 4

=item dump_groups

Returns a simplified string representation of the currently loaded
database.

    print $k->dump_groups;

You can optionally pass a match argument hashref.  Only entries
matching the criteria will be returned.

=item groups

Returns an arrayref of groups from the currently loaded database.
Groups returned will be hierarchal.  Note, groups simply returns a
reference to all of the data.  It makes no attempts at cleaning up the
data (find_groups will make sure the data is groomed).

    my $g = $k->groups;

Groups will look similar to the following:

    $g = [{
         expanded => 0,
         icon     => 0,
         id       => 234234234,
         title    => 'Foo',
         level    => 0,
         entries => [{
             accessed => "2010-06-24 15:09:19",
             bin_desc => "",
             binary   => "",
             comment  => "",
             created  => "2010-06-24 15:09:19",
             expires  => "2999-12-31 23:23:59",
             icon     => 0,
             modified => "2010-06-24 15:09:19",
             title    => "Something",
             password => 'somepass', # will be hidden if the database is locked
             url      => "",
             username => "someuser",
             id       => "0a55ac30af68149f62c072d7cc8bd5ee"
         }],
         groups => [{
             expanded => 0,
             icon     => 0,
             id       => 994414667,
             level    => 1,
             title    => "Bar"
         }],
     }];

=item header

Returns the current loaded db header.  Some fields such as cipher,
compression, protected_stream, protected_stream_key, and start_bytes
only apply to version 2 databases.

    header => {
        cipher               => "aes",
        compression          => 1,
        enc_iv               => "123456789123456", # rand
        enc_type             => "rijndael",
        header_size          => 222,
        protected_stream     => "salsa20",
        protected_stream_key => "12345678901234567890123456789012", # rand
        seed_key             => "12345678901234567890123456789012", # rand
        seed_rand            => "12345678901234567890123456789012", # rand
        seed_rot_n           => 6000,
        sig1                 => "2594363651",
        sig2                 => "3041655655",
        start_bytes          => "12345678901234567890123456789012", # rand
        ver                  => 196608,
        version              => 2,
    },

=item meta

Returns the current loaded db meta information.  Will be empty
on a version 1 database.

    meta => {
        color                         => "#4FFF00",
        custom_data                   => "",
        database_description          => "database desc",
        database_description_changed  => "2012-08-17 00:30:56",
        database_name                 => "database name",
        database_name_changed         => "2012-08-17 00:30:56",
        default_user_name             => "",
        default_user_name_changed     => "2012-08-17 00:30:34",
        entry_templates_group         => "VL5nOpzlFUevGhqL71/OTA==",
        entry_templates_group_changed => "2012-08-21 14:05:32",
        generator                     => "KeePass",
        history_max_items             => 10,
        history_max_size              => 6291456, # bytes
        last_selected_group           => "SUgL30QQqUK3tOWuNKUYJA==",
        last_top_visible_group        => "dC1sQ1NO80W7klmRhfEUVw==",
        maintenance_history_days      => 365,
        master_key_change_force       => -1,
        master_key_change_rec         => -1,
        master_key_changed            => "2012-08-17 00:30:34",
        memory_protection             => {
            notes    => 0,
            password => 1,
            title    => 0,
            url      => 0,
            username => 0
        },
        recycle_bin_changed           => "2012-08-17 00:30:34",
        recycle_bin_enabled           => 1,
        recycle_bin_uuid              => "SUgL30QQqUK3tOWuNKUYJA=="
    },

=item add_group

Adds a new group to the database.  Returns a reference to the new
group.  If a database isn't loaded, it begins a new one.  Takes a
hashref of arguments for the new entry including title, icon,
expanded.  A new random group id will be generated.  An optional group
argument can be passed.  If a group is passed the new group will be
added under that parent group.

    my $group = $k->add_group({title => 'Foo'});
    my $gid = $group->{'id'};

    my $group2 = $k->add_group({title => 'Bar', group => $gid});

The group argument's value may also be a reference to a group - such as
that returned by find_group.

=item finder_tests {

Used by find_groups and find_entries.  Takes a hashref of arguments
and returns a list of test code refs.

    {title => 'Foo'} # will check if title equals Foo
    {'title !' => 'Foo'} # will check if title does not equal Foo
    {'title =~' => qr{^Foo$}} # will check if title does matches the regex
    {'title !~' => qr{^Foo$}} # will check if title does not match the regex

=item find_groups

Takes a hashref of search criteria and returns all matching groups.
Can be passed id, title, icon, and level.  Search arguments will be
parsed by finder_tests.

    my @groups = $k->find_groups({title => 'Foo'});

    my @all_groups_flattened = $k->find_groups({});

The find_groups method also checks to make sure group ids are unique
and that all needed values are defined.

=item find_group

Calls find_groups and returns the first group found.  Dies if multiple
results are found.  In scalar context it returns only the group.  In
list context it returns the group, and its the arrayref in which it is
stored (either the root level group or a sub groups group item).

=item delete_group

Passes arguments to find_group to find the group to delete.  Then
deletes the group.  Returns the group that was just deleted.

=item add_entry

Adds a new entry to the database.  Returns a reference to the new
entry.  An optional group argument can be passed.  If a group is not
passed, the entry will be added to the first group in the database.  A
new entry id will be created if one is not passed or if it conflicts with
an existing group.

The following fields can be passed.

    accessed => "2010-06-24 15:09:19", # last accessed date
    bin_desc => "", # description of the stored binary - typically a filename
    binary   => "", # raw data to be stored in the system - typically a file
    comment  => "", # a comment for the system - auto-type info is normally here
    created  => "2010-06-24 15:09:19", # entry creation date
    expires  => "2999-12-31 23:23:59", # date entry expires
    icon     => 0, # icon number for use with agents
    modified => "2010-06-24 15:09:19", # last modified
    title    => "Something",
    password => 'somepass', # will be hidden if the database is locked
    url      => "",
    username => "someuser",
    id       => "0a55ac30af68149f62c072d7cc8bd5ee" # randomly generated automatically

    group    => $gid, # which group to add the entry to

The group argument's value may also be a reference to a group - such as
that returned by find_group.

=item find_entries

Takes a hashref of search criteria and returns all matching groups.
Can be passed an entry id, title, username, comment, url, active,
group_id, group_title, or any other entry property.  Search arguments
will be parsed by finder_tests.

    my @entries = $k->find_entries({title => 'Something'});

    my @all_entries_flattened = $k->find_entries({});

=item find_entry

Calls find_entries and returns the first entry found.  Dies if
multiple results are found.  In scalar context it returns only the
entry.  In list context it returns the entry, and its group.

=item delete_entry

Passes arguments to find_entry to find the entry to delete.  Then
deletes the entry.  Returns the entry that was just deleted.

=item locked_entry_password

Allows access to individual passwords for a database that is locked.
Dies if the database is not locked.

=back

=head1 UTILITY METHODS

The following methods are general purpose methods used during the
parsing and generating of kdb databases.

=over 4

=item now

Returns the current localtime datetime stamp.

=item default_exp

Returns the string representing the default expires time of an entry.
Will use $self->{'default_exp'} or fails to the string '2999-12-31
23:23:59'.

=item decrypt_rijndael_cbc

Takes an encrypted string, a key, and an encryption_iv string.
Returns a plaintext string.

=item encrypt_rijndael_cbc

Takes a plaintext string, a key, and an encryption_iv string.  Returns
an encrypted string.

=item decode_base64

Loads the MIME::Base64 library and decodes the passed string.

=item unchunksum

Parses and reassembles a buffer, reading in lengths, and checksums
of chunks.

=item decompress

Loads the Compress::Zlib library and unzips the contents.

=item parse_xml

Loads the XML::Parser library and sets up a basic parser that can call
hooks at various events.  Without the hooks, it runs similarly to
XML::Simple::parse.

    my $data = $self->parse_xml($buffer, {
        top            => 'KeePassFile',
        force_array    => {Group => 1, Entry => 1},
        start_handlers => {Group => sub { $level++ }},
        end_handlers   => {Group => sub { $level-- }},
    });

=item salsa20

Takes a hashref containing a salsa20 key string (length 32 or 16), a
salsa20 iv string (length 8), number of salsa20 rounds (8, 12, or 20 -
default 20), and an optional data string.  The key and iv are used to
initialize the salsa20 encryption.

If a data string is passed, the string is salsa20 encrypted and
returned.

If no data string is passed a salsa20 encrypting coderef is returned.

    my $encoded = $self->salsa20({key => $key, iv => $iv, data => $data});
    my $uncoded = $self->salsa20({key => $key, iv => $iv, data => $encoded});
    # $data eq $uncoded

    my $encoder = $self->salsa20({key => $key, iv => $Iv}); # no data
    my $encoded = $encoder->($data);
    my $part2   = $encoder->($more_data); # continues from previous state

=item salsa20_stream

Takes a hashref that will be passed to salsa20.  Uses the resulting
encoder to generate a more continuous encoded stream.  The salsa20
method encodes in chunks of 64 bytes.  If a string is not a multiple
of 64, then some of the xor bytes are unused.  The salsa20_stream
method maintains a buffer of xor bytes to ensure that none are wasted.

    my $encoder = $self->salsa20_stream({key => $key, iv => $Iv}); # no data
    my $encoded = $encoder->("1234");   # calls salsa20->()
    my $part2   = $encoder->("1234");   # uses the same pad until 64 bytes are used

=back

=head1 OTHER METHODS

=over 4

=item _parse_v1_header

=item _parse_v1_body

=item _parse_v1_groups

=item _parse_v1_entries

=item _parse_v1_date

Utilities used for parsing version 1 type databases.

=item _parse_v2_header

=item _parse_v2_body

=item _parse_v2_date

Utilities used for parsing version 2 type databases.

=item _gen_v1_header

=item _gen_v1_db

=item _gen_v1_date

Utilities used to generate version 1 type databases.

=item _gen_v2_header

=item _gen_v2_db

Utilities used to generate version 2 type databases.

=item _master_v1_key

=item _master_v2_key

Takes the password and parsed headers.  Returns the
master key based on database type.

=back

=head1 BUGS

Only Rijndael is supported.

Only passkeys are supported (no key files).

This module makes no attempt to act as a password agent.  That is the
job of File::KeePass::Agent.  This isn't really a bug but some people
will think it is.

Groups and entries don't have true objects associated with them.  At
the moment this is by design.  The data is kept as plain boring data.

=head1 SOURCES

Knowledge about the KeePass DB v1 format was gleaned from the source
code of keepassx-0.4.3.  That source code is published under the GPL2
license.  KeePassX 0.4.3 bears the copyright of

    Copyright (C) 2005-2008 Tarek Saidi <tarek.saidi@arcor.de>
    Copyright (C) 2007-2009 Felix Geyer <debfx-keepassx {at} fobos.de>

Knowledge about the KeePass DB v2 format was gleaned from the source
code of keepassx-2.0-alpha1.  That source code is published under the
GPL2 or GPL3 license.  KeePassX 2.0-alpha1 bears the copyright of

    Copyright: 2010-2012, Felix Geyer <debfx@fobos.de>
               2011-2012, Florian Geyer <blueice@fobos.de>

The salsa20 algorithm is based on
http://cr.yp.to/snuffle/salsa20/regs/salsa20.c which is listed as
Public domain (D. J. Bernstein).

The ordering and layering of encryption/decryption algorithms of
File::KeePass are of derivative nature from KeePassX and could not
have been created without this insight - though the perl code is from
scratch.

=head1 AUTHOR

Paul Seamons <paul at seamons dot com>

=head1 LICENSE

This module may be distributed under the same terms as Perl itself.

=cut
