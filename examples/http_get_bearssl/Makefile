PROGRAM=http_get_bearssl
EXTRA_COMPONENTS = \
		extras/bearssl \
 		extras/http-parser \
		$(abspath ../../components/esp8266-open-rtos/cJSON) \
		$(abspath ../../components/common/wolfssl) \
		$(abspath ../../components/common/homekit)

EXTRA_CFLAGS +=-DCONFIG_EPOCH_TIME=$(shell date --utc '+%s') -DHOMEKIT_SHORT_APPLE_UUIDS

EXTRA_CFLAGS += -I../.. 

include $(SDK_PATH)/common.mk

monitor:
	rlwrap picocom $(ESPPORT) --baud 921600 --omap crcrlf
