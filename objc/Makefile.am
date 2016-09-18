ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

bin_PROGRAMS = cloudignore
cloudignore_SOURCES = the_silver_searcher/src/ignore.c the_silver_searcher/src/ignore.h \
			 the_silver_searcher/src/log.c the_silver_searcher/src/log.h \
			 the_silver_searcher/src/options.c the_silver_searcher/src/options.h \
			 the_silver_searcher/src/print.c the_silver_searcher/src/print_w32.c \
			 the_silver_searcher/src/print.h the_silver_searcher/src/scandir.c \
			 the_silver_searcher/src/scandir.h the_silver_searcher/src/search.c \
			 the_silver_searcher/src/search.h the_silver_searcher/src/lang.c \
			 the_silver_searcher/src/lang.h the_silver_searcher/src/util.c \
			 the_silver_searcher/src/util.h the_silver_searcher/src/decompress.c \
			 the_silver_searcher/src/decompress.h the_silver_searcher/src/uthash.h \
			 the_silver_searcher/src/main.c ./Support/NSError+POSIX.m \
			 LoopbackFS.m loop.m
cloudignore_LDADD = ${PCRE_LIBS} ${LZMA_LIBS} ${ZLIB_LIBS} $(PTHREAD_LIBS)

.PHONY : all clean
