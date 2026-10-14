LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE     := ih8securelock
LOCAL_SRC_FILES  := module.cpp binder.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS := -Wall -Wextra -Wshadow -Wformat=2 -Werror \
                -D_FORTIFY_SOURCE=2 \
                -O2 \
                -fstack-protector-strong \
                -fvisibility=hidden \
                -ffunction-sections \
                -fdata-sections

LOCAL_CPPFLAGS += -fvisibility-inlines-hidden

LOCAL_LDFLAGS += -Wl,-z,relro \
                 -Wl,-z,now \
                 -Wl,-z,noexecstack \
                 -Wl,--gc-sections \
                 -Wl,--icf=all \
                 -Wl,--build-id=sha1 \
                 -Wl,--exclude-libs,ALL

ifneq ($(filter arm64-v8a x86_64,$(TARGET_ARCH_ABI)),)
LOCAL_LDFLAGS += -Wl,-z,max-page-size=16384
endif

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
