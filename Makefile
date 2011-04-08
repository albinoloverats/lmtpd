.PHONY: clean distclean

vpath %.c src

APP      = lmtpd
OBJ      = lmtpd.o common/common.o common/list.o common/logging.o
COMMON   = common.o list.o logging.o

CONF     = lmtpd.conf
INIT_S   = lmtpd
INIT_L   = lmtpd.init

CFLAGS   = -Wall -Wextra -Wno-unused-parameter -O0 -std=gnu99 `libgcrypt-config --cflags` -c -ggdb -o
CPPFLAGS = -I. -Isrc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS  = -r -o

$(APP): $(OBJ) common
	@$(CC) -o $(APP) $(OBJ)
	@echo "built \`$(OBJ)' --> \`$(APP)'"

%.o: %.c
	@$(CC) $(CPPFLAGS) $(CFLAGS) $@ $<
	@echo "compiled \`$<' --> \`$@'"

$(common):
	@$(MAKE) -C common $(COMMON)


install:
	 @install -c -m 755 -s -D -T $(APP) $(PREFIX)/usr/sbin/$(APP)
	-@echo "installed \`$(APP)' --> \`$(PREFIX)/usr/sbin/$(APP)'"
	 @install -c -m 644 -D -T $(CONF) $(PREFIX)/etc/$(CONF)
	-@echo "installed \`$(CONF)' --> \`$(PREFIX)/etc/$(CONF)'"
	 @install -c -m 755 -D -T $(INIT_L) $(PREFIX)/etc/rc.d/$(INIT_S)
	-@echo "installed \`$(INIT_L)' --> \`$(PREFIX)/etc/rc.d/$(INIT_S)'"

uninstall:
	-@echo "TODO!!!"

clean:
	-@rm -fv $(OBJ)
	@$(MAKE) -C common clean

distclean: clean
	-@rm -fv $(APP)
	@$(MAKE) -C common distclean
