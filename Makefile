.PHONY: lmtpd clean

OPTIONS := -g -o lmtpd -std=c99 -Wall -Wextra -O0 -pipe -ldl -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I ./
COMMON  := common/common.c common/list.c src/lmtpd.c

lmtpd:
# build the main executible
	 @gcc $(OPTIONS) $(COMMON)
	-@echo "compiled \`src/lmtpd.c common/common.c common/list.c' --> \`lmtpd'"

clean:
	-@rm -fv lmtpd

