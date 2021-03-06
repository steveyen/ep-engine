ACLOCAL_AMFLAGS = -I m4 --force
bin_SCRIPTS = management/analyze_core \
              wrapper/mbadm-online-restore \
              wrapper/mbadm-online-update \
              wrapper/mbadm-tap-registration \
              wrapper/mbbackup \
              wrapper/mbbackup-incremental \
              wrapper/mbdbconvert \
              wrapper/mbdbmaint \
              wrapper/mbdbupgrade \
              wrapper/mbflushctl \
              wrapper/mbrestore \
              wrapper/mbstats \
              wrapper/mbvbucketctl

memcachedlibdir = $(libdir)/memcached
memcachedlib_LTLIBRARIES = ep.la ep_testsuite.la timing_tests.la
noinst_LTLIBRARIES = libkvstore.la libobjectregistry.la

bin_PROGRAMS = management/mbdbconvert
BUILT_SOURCES =
CLEANFILES = mbbackup-0001.mbb mbbackup-0002.mbb

EXTRA_DIST = docs management README.markdown win32 Doxyfile LICENSE

noinst_PROGRAMS = sizes

man_MANS =
if BUILD_DOCS
man_MANS += mbadm-online-update.1m \
            mbbackup-incremental.1m
endif

mbadm-online-update.1m: docs/mbadm-online-update.pod
	${POD2MAN} -c "$*" -r "" -s 1m $< $@

mbbackup-incremental.1m: docs/mbbackup-incremental.pod
	${POD2MAN} -c "$*" -r "" -s 1m $< $@

ep_la_CPPFLAGS = -I$(top_srcdir) $(AM_CPPFLAGS)
ep_la_LDFLAGS = -module -dynamic
ep_la_SOURCES = \
                 atomic/gcc_atomics.h \
                 atomic/libatomic.h \
                 atomic.hh \
                 callbacks.hh \
                 checkpoint.hh \
                 checkpoint.cc \
                 checkpoint_remover.hh \
                 checkpoint_remover.cc \
                 command_ids.h \
                 common.hh \
                 config_static.h \
                 dispatcher.cc dispatcher.hh \
                 ep.cc ep.hh \
                 ep_engine.cc ep_engine.h \
                 ep_extension.cc ep_extension.h \
                 flusher.cc flusher.hh \
                 histo.hh \
                 htresizer.cc htresizer.hh \
                 item.cc item.hh \
                 item_pager.cc item_pager.hh \
                 kvstore.hh \
                 locks.hh \
                 mutex.hh \
                 priority.cc priority.hh \
                 queueditem.cc queueditem.hh \
                 restore.hh \
                 restore_impl.cc \
                 ringbuffer.hh \
                 sizes.cc \
                 stats.hh \
                 statsnap.cc statsnap.hh \
                 stored-value.cc stored-value.hh \
                 syncobject.hh \
                 sync_registry.cc sync_registry.hh \
                 tapconnection.cc tapconnection.hh \
                 tapconnmap.cc tapconnmap.hh \
                 tapthrottle.cc tapthrottle.hh \
                 vbucket.cc vbucket.hh

if BUILD_BYTEORDER
ep_la_SOURCES += byteorder.c
endif

libobjectregistry_la_SOURCES = objectregistry.cc objectregistry.hh


libkvstore_la_SOURCES = kvstore.cc kvstore.hh \
                        pathexpand.hh pathexpand.cc \
                        sqlite-eval.cc sqlite-eval.hh \
                        sqlite-kvstore.cc sqlite-kvstore.hh \
                        sqlite-pst.cc sqlite-pst.hh \
                        sqlite-strategies.cc sqlite-strategies.hh
libkvstore_la_LIBADD =
libkvstore_la_DEPENDENCIES =

ep_la_LIBADD = libkvstore.la libobjectregistry.la
ep_la_DEPENDENCIES = libkvstore.la libobjectregistry.la
ep_testsuite_la_LIBADD = libkvstore.la libobjectregistry.la
ep_testsuite_la_DEPENDENCIES = libkvstore.la libobjectregistry.la

management_mbdbconvert_SOURCES = management/dbconvert.cc \
                                 testlogger.cc
management_mbdbconvert_LDADD = libkvstore.la libobjectregistry.la
management_mbdbconvert_DEPENDENCIES = libkvstore.la libobjectregistry.la

if BUILD_EMBEDDED_LIBSQLITE3
ep_la_LIBADD += libsqlite3.la
ep_la_DEPENDENCIES += libsqlite3.la
ep_testsuite_la_LIBADD += libsqlite3.la
ep_testsuite_la_DEPENDENCIES += libsqlite3.la
management_mbdbconvert_LDADD += libsqlite3.la
management_mbdbconvert_DEPENDENCIES += libsqlite3.la
noinst_LTLIBRARIES += libsqlite3.la
bin_PROGRAMS += management/sqlite3
else
ep_la_LIBADD += $(LIBSQLITE3)
ep_testsuite_la_LIBADD += $(LIBSQLITE3)
management_mbdbconvert_LDADD += $(LIBSQLITE3)
endif

libsqlite3_la_SOURCES = embedded/sqlite3.h embedded/sqlite3.c
libsqlite3_la_CFLAGS = $(AM_CFLAGS) ${NO_WERROR} -DSQLITE_THREADSAFE=2

check_PROGRAMS=atomic_test atomic_ptr_test atomic_queue_test hash_table_test priority_test vbucket_test checkpoint_test dispatcher_test misc_test hrtime_test histo_test chunk_creation_test ringbuffer_test vb_del_chunk_list_test pathexpand_test

TESTS=${check_PROGRAMS}
EXTRA_TESTS =

ep_testsuite_la_CFLAGS = $(AM_CFLAGS) ${NO_WERROR}
ep_testsuite_la_SOURCES= ep_testsuite.cc ep_testsuite.h \
                         locks.hh mutex.hh testlogger_libify.cc
ep_testsuite_la_LDFLAGS= -module -dynamic

# This is because automake can't figure out how to build the same code
# for two different targets.
testlogger_libify.cc: testlogger.cc
	cp $(top_srcdir)/testlogger.cc testlogger_libify.cc

if BUILD_GENERATED_TESTS
memcachedlib_LTLIBRARIES += generated_suite.la

.genstamp: t/gen_engine_test.py t/breakdancer.py
	${top_srcdir}/t/gen_engine_test.py
	touch .genstamp

GEN_FILES=generated_suite_0.c \
          generated_suite_1.c \
          generated_suite_2.c \
          generated_suite_3.c \
          generated_suite_4.c \
          generated_suite_5.c \
          generated_suite_6.c \
          generated_suite_7.c \
          generated_suite_8.c \
          generated_suite_9.c


$(GEN_FILES): .genstamp suite_stubs.h
BUILT_SOURCES+= $(GEN_FILES)
CLEANFILES+= $(GEN_FILES) .genstamp

generated_suite_la_DEPENDENCIES = ep.la
generated_suite_la_CFLAGS = $(AM_CFLAGS) -O0
nodist_generated_suite_la_SOURCES = $(GEN_FILES)
generated_suite_la_SOURCES= suite_stubs.c ep_testsuite.h
generated_suite_la_LDFLAGS= -module -dynamic

EXTRA_TESTS += generated_engine_tests

GENERATED_TEST_TIMEOUT=5

generated_engine_tests: generated_suite.la
	$(ENGINE_TESTAPP) -E .libs/ep.so -t $(GENERATED_TEST_TIMEOUT) \
		-. -q -T .libs/generated_suite.so \
		-e 'ht_size=13;ht_locks=7;db_strategy=singleDB;dbname=:memory:'
endif

timing_tests_la_CFLAGS = $(AM_CFLAGS) ${NO_WERROR}
timing_tests_la_SOURCES= timing_tests.cc
timing_tests_la_LDFLAGS= -module -dynamic

atomic_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
atomic_test_SOURCES = t/atomic_test.cc atomic.hh
atomic_test_DEPENDENCIES = atomic.hh

atomic_ptr_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
atomic_ptr_test_SOURCES = t/atomic_ptr_test.cc atomic.hh
atomic_ptr_test_DEPENDENCIES = atomic.hh

atomic_queue_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
atomic_queue_test_SOURCES = t/atomic_queue_test.cc atomic.hh
atomic_queue_test_DEPENDENCIES = atomic.hh

dispatcher_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
dispatcher_test_SOURCES = t/dispatcher_test.cc dispatcher.cc dispatcher.hh priority.cc priority.hh testlogger.cc
dispatcher_test_DEPENDENCIES = common.hh dispatcher.hh dispatcher.cc priority.cc priority.hh libobjectregistry.la
dispatcher_test_LDADD = libobjectregistry.la

hash_table_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
hash_table_test_SOURCES = t/hash_table_test.cc item.cc stored-value.cc stored-value.hh \
                          testlogger.cc
hash_table_test_DEPENDENCIES = stored-value.cc stored-value.hh ep.hh item.hh \
                               libobjectregistry.la
hash_table_test_LDADD = libobjectregistry.la

misc_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
misc_test_SOURCES = t/misc_test.cc common.hh
misc_test_DEPENDENCIES = common.hh

priority_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
priority_test_SOURCES = t/priority_test.cc priority.hh priority.cc

sizes_CPPFLAGS = -I$(top_srcdir) $(AM_CPPFLAGS)
sizes_SOURCES = sizes.cc
sizes_DEPENDENCIES = vbucket.hh stored-value.hh item.hh

management_sqlite3_SOURCES = embedded/sqlite3-shell.c
management_sqlite3_CFLAGS = $(AM_CFLAGS) ${NO_WERROR}
management_sqlite3_DEPENDENCIES = libsqlite3.la
management_sqlite3_LDADD = libsqlite3.la

vbucket_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
vbucket_test_SOURCES = t/vbucket_test.cc t/threadtests.hh vbucket.hh vbucket.cc stored-value.cc stored-value.hh testlogger.cc \
		       checkpoint.hh checkpoint.cc
vbucket_test_DEPENDENCIES = vbucket.hh stored-value.cc stored-value.hh checkpoint.hh checkpoint.cc libobjectregistry.la
vbucket_test_LDADD = libobjectregistry.la

checkpoint_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
checkpoint_test_SOURCES = t/checkpoint_test.cc checkpoint.hh checkpoint.cc vbucket.hh vbucket.cc \
			  testlogger.cc stored-value.cc stored-value.hh queueditem.hh
checkpoint_test_DEPENDENCIES = checkpoint.hh vbucket.hh stored-value.cc stored-value.hh queueditem.hh libobjectregistry.la
checkpoint_test_LDADD = libobjectregistry.la

hrtime_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
hrtime_test_SOURCES = t/hrtime_test.cc common.hh

histo_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
histo_test_SOURCES = t/histo_test.cc common.hh histo.hh
histo_test_DEPENDENCIES = common.hh histo.hh

chunk_creation_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
chunk_creation_test_SOURCES = t/chunk_creation_test.cc common.hh

pathexpand_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
pathexpand_test_SOURCES = t/pathexpand_test.cc pathexpand.hh pathexpand.cc

ringbuffer_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
ringbuffer_test_SOURCES = t/ringbuffer_test.cc ringbuffer.hh
ringbuffer_test_DEPENDENCIES = ringbuffer.hh

vb_del_chunk_list_test_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir) ${NO_WERROR}
vb_del_chunk_list_test_SOURCES = t/vb_del_chunk_list_test.cc ep.hh
vb_del_chunk_list_test_DEPENDENCIES = ep.hh

if BUILD_GETHRTIME
ep_la_SOURCES += gethrtime.c
hrtime_test_SOURCES += gethrtime.c
dispatcher_test_SOURCES += gethrtime.c
vbucket_test_SOURCES += gethrtime.c
checkpoint_test_SOURCES += gethrtime.c
endif

pythonlibdir=$(libdir)/python
pythonlib_DATA= \
                management/capture.py \
                management/clitool.py \
                management/mc_bin_client.py \
                management/mc_bin_server.py \
                management/memcacheConstants.py \
                management/tap.py

pythonlib_SCRIPTS= \
                management/mbadm-online-restore \
                management/mbadm-online-update \
                management/mbadm-tap-registration \
                management/mbbackup \
                management/mbbackup-incremental \
                management/mbdbconvert \
                management/mbdbmaint \
                management/mbdbupgrade \
                management/mbflushctl \
                management/mbrestore \
                management/mbstats \
                management/mbvbucketctl

PYTHON_TOOLS= \
              wrapper/mbadm-online-restore \
              wrapper/mbadm-online-update \
              wrapper/mbadm-tap-registration \
              wrapper/mbbackup \
              wrapper/mbbackup-incremental \
              wrapper/mbdbconvert \
              wrapper/mbdbmaint \
              wrapper/mbdbupgrade \
              wrapper/mbflushctl \
              wrapper/mbrestore \
              wrapper/mbstats \
              wrapper/mbvbucketctl

${PYTHON_TOOLS}: wrapper/wrapper
	cp $< $@

BUILT_SOURCES += ${PYTHON_TOOLS}
CLEANFILES+= ${PYTHON_TOOLS}

TEST_TIMEOUT=30

mbbackup-0002.mbb: $(top_srcdir)/t/generate-mbbackup
	echo "Generate incremental restore files used by the test suite"
	@$(top_srcdir)/t/generate-mbbackup

engine_tests: ep.la ep_testsuite.la mbbackup-0002.mbb
	$(ENGINE_TESTAPP) -E .libs/ep.so -t $(TEST_TIMEOUT) \
		-T .libs/ep_testsuite.so \
		-e 'ht_size=13;ht_locks=7;initfile=t/test_pragma.sql;min_data_age=0;db_strategy=multiDB'

test: all check-TESTS engine_tests sizes
	./sizes
