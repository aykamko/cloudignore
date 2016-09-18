dropboxpp_objc:
	gcc -o dropboxpp_objc ./Support/NSError+POSIX.m LoopbackFS.m loop.m ./the_silver_searcher/src/*.c \
		-I./Support -I./the_silver_searcher/src \
		-framework OSXFUSE -framework Foundation

install:
	cp dropboxpp_objc /usr/local/bin/dropboxpp_objc

clean:
	rm -rf dropboxpp_objc
