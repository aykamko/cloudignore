dropboxpp_objc:
	gcc -o dropboxpp_objc ../Support/NSError+POSIX.m LoopbackFS.m loop.m -I../Support -framework OSXFUSE -framework Foundation

install:
	cp dropboxpp_objc /usr/local/bin/dropboxpp_objc
