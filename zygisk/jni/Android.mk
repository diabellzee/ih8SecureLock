LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE     := ih8securelock
LOCAL_SRC_FILES  := module.cpp binder.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)

# Flags common to C and C++ compilation. Kept out of LOCAL_CPPFLAGS (and not
# derived from it via a blanket `LOCAL_CFLAGS := $(LOCAL_CPPFLAGS)` copy, as
# this used to do) so that a future .c file added to LOCAL_SRC_FILES can't
# silently inherit a C++-only flag it can't use: -std=c++20 specifically is
# a hard `error: invalid argument '-std=c++20' not allowed with 'C'` under
# the NDK's clang, not just a warning -- verified directly against clang,
# since gcc alone only warns and would have hidden this in local testing.
#
# -Werror is safe to add now that module.cpp's #include of the vendored
# zygisk.hpp (which we don't own/control, see the cppcheck suppressions in
# build.yml for the same reasoning) is wrapped in a diagnostic push/ignore/
# pop below -Wall/-Wextra/-Wshadow findings from that one header can no
# longer fail our own build, while every finding in module.cpp/binder.cpp/
# binder.hpp themselves still does.
LOCAL_CFLAGS := -Wall -Wextra -Wshadow -Wformat=2 -Werror \
                -D_FORTIFY_SOURCE=2 \
                -O2 \
                -fstack-protector-strong \
                -fvisibility=hidden \
                -ffunction-sections \
                -fdata-sections

# C++-only. -std=c++20/-fno-rtti/-fno-exceptions are intentionally NOT
# repeated here: Application.mk's APP_CPPFLAGS already applies them
# project-wide (and, unlike LOCAL_CFLAGS above, APP_CPPFLAGS only ever
# reaches C++ files to begin with) -- one source of truth instead of two
# copies that could quietly drift apart.
LOCAL_CPPFLAGS += -fvisibility-inlines-hidden

LOCAL_LDFLAGS += -Wl,-z,relro \
                 -Wl,-z,now \
                 -Wl,-z,noexecstack \
                 -Wl,--gc-sections \
                 -Wl,--icf=all \
                 -Wl,--build-id=sha1 \
                 -Wl,--exclude-libs,ALL

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
