use Config;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

sub MY::postamble {
	'
libiptc/libiptc.a: libiptc/*.c
	make -C libiptc/ all

all::
	make -C modules/ all

install::
	make -C modules/ install

clean::
	make -C modules/ clean
	make -C libiptc/ clean

	';
};

WriteMakefile(
    'NAME'	=> 'IPTables::IPv4',
    'VERSION_FROM' => 'IPv4.pm', # finds $VERSION
    'OBJECT'	=> 'IPv4.o loader.o packer.o unpacker.o maskgen.o libiptc/libiptc.a',
    'INC'	=> '-Iinclude -I/usr/src/linux/include',
    'CCFLAGS'	=> "-Wall -DMODULE_PATH=\\\"$Config{siteprefixexp}/lib/IPTables-IPv4\\\"",
    'TYPEMAPS'	=> ['IPTables.typemap'],
    'XSPROTOARG' => '-noprototypes',
);
