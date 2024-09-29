BUSYBOX_VERSION=1.36.1
BUSYBOX=busybox-$(BUSYBOX_VERSION)

.PHONY: all build-busybox
all: build-busybox

build-busybox: build/.patched build/.config
	make -C $(BUSYBOX) O="$(shell pwd)/build" -j 30
	make -C $(BUSYBOX) O="$(shell pwd)/build" install

$(BUSYBOX).tar.bz2:
	wget "https://busybox.net/downloads/$@"

build/.extracted: $(BUSYBOX).tar.bz2
	mkdir -p build
	rm -rf $(BUSYBOX)/
	tar -xf $<
	touch $@

build/.patched: build/.extracted
	set -e; cat *.patch | (cd $(BUSYBOX); patch -p1)
	touch $@

build/.config: busybox.config
	mkdir -p build
	cp $< $@
