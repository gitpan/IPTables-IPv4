use Config;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $moduledir = $Config{siteprefixexp} . "/lib/IPTables-IPv4";

{
	package MY;

	sub test_via_harness {
		my($self, $perl, $tests) = @_;
		return $self->SUPER::test_via_harness("IPT_IPV4_MODPATH=\$(CURDIR)/modules $perl", $tests);
	}

	sub test_via_script {
		my($self, $perl, $tests) = @_;
		return $self->SUPER::test_via_script("IPT_IPV4_MODPATH=\$(CURDIR)/modules $perl", $tests);
	}

	sub postamble {
	"
libiptc/libiptc.a: libiptc/*.c
	make -C libiptc/ all

pure_all:: modules
	make -C modules/ all INSTALL_DIR=$moduledir

install::
	make -C modules/ install INSTALL_DIR=$moduledir

clean::
	make -C modules/ clean
	make -C libiptc/ clean

";
	}
}

WriteMakefile(
    'NAME'	=> 'IPTables::IPv4',
    'VERSION_FROM' => 'IPv4.pm', # finds $VERSION
    'OBJECT'	=> 'IPv4.o loader.o packer.o unpacker.o maskgen.o libiptc/libiptc.a',
    'INC'	=> '-Iinclude -I/usr/src/linux/include',
    'CCFLAGS'	=> "-Wall -DMODULE_PATH=\\\"$moduledir\\\"" . (defined $Config{'use64bitint'} ? " -DPERL_USES_64BIT_INT" : ""),
    'TYPEMAPS'	=> ['IPTables.typemap'],
    'XSPROTOARG' => '-noprototypes',
);
