.PHONY: clean distclean

vpath %.c src

common	 = common/clib.a
obj      = lmtpd.o
app      = lmtpd

conf     = lmtpd.conf
init_s   = lmtpd
init_l   = lmtpd.init

CFLAGS   = -Wall -Wextra -Wno-unused-parameter -O2 -std=gnu99 -c -o
CPPFLAGS = -I. -Isrc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS  = -r -s -o

all: $(obj) $(common)
	@$(CC) -o $(app) $(obj) $(common)
	@echo "built \`$(obj) $(common)' --> \`$(app)'"

%.o: %.c
	@$(CC) $(CPPFLAGS) $(CFLAGS) $@ $<
	@echo "compiled \`$<' --> \`$@'"

$(common):
	@$(MAKE) -C common

install:
	 @install -c -m 755 -s -D -T $(app) $(PREFIX)/usr/sbin/$(app)
	-@echo "installed \`$(app)' --> \`$(PREFIX)/usr/sbin/$(app)'"
	 @install -c -m 644 -D -T $(conf) $(PREFIX)/etc/$(conf)
	-@echo "installed \`$(conf)' --> \`$(PREFIX)/etc/$(conf)'"
	 @install -c -m 755 -D -T $(init_l) $(PREFIX)/etc/rc.d/$(init_s)
	-@echo "installed \`$(init_l)' --> \`$(PREFIX)/etc/rc.d/$(init_s)'"

uninstall:
	-@echo "TODO!!!"

clean:
	-@rm -fv $(obj)
	@$(MAKE) -C common clean

distclean: clean
	-@rm -fv $(app)
	@$(MAKE) -C common distclean
