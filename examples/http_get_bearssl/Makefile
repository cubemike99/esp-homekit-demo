PROGRAM=http_get_bearssl
EXTRA_COMPONENTS = \
		extras/bearssl \
 		extras/http-parser

EXTRA_CFLAGS +=-DCONFIG_EPOCH_TIME=$(shell date --utc '+%s')

EXTRA_CFLAGS += -I../.. 

include $(SDK_PATH)/common.mk

monitor:
	rlwrap picocom $(ESPPORT) --baud 921600 --omap crcrlf
