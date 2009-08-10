SUBDIRS = ulibc common metsrv ext_posix_sample

subdirs:
	for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir; \
	done



.PHONY:
clean:
	for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir clean; \
	done