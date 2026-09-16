# src/test/modules/waldemort/Makefile

PGFILEDESC = "WALdemort - generate and corrupt WAL for testing"
PGAPPICON = win32

TAP_TESTS = 1

OBJS = waldemort.o xlogreader.o $(WIN32RES)
EXTRA_CLEAN = waldemort$(X) xlogreader.c

subdir = src/test/modules/waldemort
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk

override CPPFLAGS := -DFRONTEND $(CPPFLAGS)

all: waldemort$(X)

waldemort$(X): $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(PG_LIBS_INTERNAL) $(LDFLAGS) $(LDFLAGS_EX) $(PG_LIBS) $(LIBS) -o $@

xlogreader.c: % : $(top_srcdir)/src/backend/access/transam/%
	rm -f $@ && $(LN_S) $< .
