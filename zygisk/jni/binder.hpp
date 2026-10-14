#pragma once

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define ARR_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define STR_LEN(a) (ARR_LEN(a) - 1)

// Helpers to build JNI class / field names for AIDL-generated stubs, e.g.
// BINDER_STUB("android/view/IWindowSession")  -> "android/view/IWindowSession$Stub"
// BINDER_TRSCTN("relayout")                   -> "TRANSACTION_relayout"
#define BINDER_STUB(n) (n "$Stub")
#define BINDER_TRSCTN(n) ("TRANSACTION_" n)

// Does the (descLen, desc) pair read out of a Parcel match this literal
// interface descriptor? The length is compared first so memcmp never reads
// past what FakeParcel::readString16() has already bounds-checked.
#define BINDER_DESC_CMP(descLit, desc, descLen) \
    (STR_LEN(descLit) == (descLen) &&           \
     memcmp((desc), (descLit), (descLen) * sizeof(char16_t)) == 0)

// sizeof(struct flat_binder_object), which depends on the *binder protocol*
// (i.e. how libbinder was built to match the kernel driver), not on whether
// the current process is 32- or 64-bit:
//
//  * 64-bit binder protocol (version 8): binder_uintptr_t is __u64, so
//    hdr(4) + flags(4) + binder/handle(8) + cookie(8) = 24 bytes -- in
//    64-bit *and* 32-bit processes. Every device launching with Android P or
//    later must use it, even on 32-bit SoCs, and the kernel's old 32-bit
//    option (CONFIG_ANDROID_BINDER_IPC_32BIT) is documented as breaking
//    newer Android userspace and was later removed.
//  * Legacy 32-bit protocol (version 7, Android 4.4-era kernels still found
//    on a few old 32-bit devices running custom Android 10+ ROMs):
//    binder_uintptr_t is __u32 -> 16 bytes, only in 32-bit processes.
//
// The previous `#if defined(__LP64__) 24 #else 16` therefore mis-sized the
// object in every 32-bit process on a modern device. See
// FakeParcel::skipFlatObj() for how the right size is picked at runtime.
constexpr uint32_t kFlatBinderObjSize64 = 24;
constexpr uint32_t kFlatBinderObjSize32Legacy = 16;
// hdr.type of a strong *local* binder: B_PACK_CHARS('s', 'b', '*', 0x85).
constexpr uint32_t kBinderTypeBinder = 0x73622a85u;

struct PParcel {
    // Layout must mirror the real android::Parcel object we alias onto via
    // pointer-cast in module.cpp, so `error` stays even though nothing here
    // reads it directly.
    // cppcheck-suppress unusedStructMember
    size_t error;
    // Read as pparcel->data in module.cpp's transactHook(); cppcheck checks
    // this header on its own and can't see that cross-TU use.
    // cppcheck-suppress unusedStructMember
    char* data;
    // Read as pparcel->data_size in module.cpp's transactHook(); same
    // cross-TU reason as `data` above.
    // cppcheck-suppress unusedStructMember
    size_t data_size;
};

// Bounds-checked cursor over a raw Parcel buffer.
//
// The cursor tracks the buffer length itself and "poisons" the parcel
// (valid = false) the moment any operation would run past the end, after
// which every further op is a cheap no-op that returns 0/nullptr instead of
// touching memory. Callers only need to check ok() (or a null return) once,
// at the point they're about to use the result.
struct FakeParcel {
   private:
    char* data;
    size_t cur;
    size_t size;
    bool valid;

    // Returns true iff reading/skipping `n` more bytes from `cur` stays
    // within `size`. Uses uint64_t so the check itself can't overflow on
    // 32-bit ABIs (armeabi-v7a/x86) where size_t is only 32 bits.
    inline bool ensure(uint64_t n) {
        if (!valid || (uint64_t)cur + n > (uint64_t)size) {
            valid = false;
            return false;
        }
        return true;
    }

   public:
    FakeParcel(char* data_in, size_t size_in);

    inline bool ok() const { return valid; }
    void skip(uint32_t n);

    // Skip the IWindow strong-binder object. Picks the right implementation
    // for the current process; see the two variants below.
    void skipFlatObj();
    // 64-bit binder protocol: always kFlatBinderObjSize64 bytes.
    void skipFlatObj64();
    // 32-bit process: the object is 24 bytes (64-bit protocol) or 16 bytes
    // (legacy protocol). Told apart from the object's own bytes; poisons the
    // parcel if it can't be told, so callers fail closed.
    void skipFlatObj32();

    uint32_t* peekInt32Ref();
    uint32_t readInt32();
    char16_t* readString16(uint32_t len);
};

inline FakeParcel::FakeParcel(char* data_in, size_t size_in)
    : data(data_in), cur(0), size(size_in), valid(data_in != nullptr) {}

inline void FakeParcel::skip(uint32_t n) {
    if (ensure(n)) cur += n;
}

inline void FakeParcel::skipFlatObj64() { skip(kFlatBinderObjSize64); }

inline void FakeParcel::skipFlatObj32() {
    // Need at least the 16 bytes common to both layouts to look at.
    if (!ensure(kFlatBinderObjSize32Legacy)) return;
    uint32_t type, word3;
    memcpy(&type, data + cur, sizeof(type));
    memcpy(&word3, data + cur + 12, sizeof(word3));
    // The IWindow handed to IWindowSession.relayout*() is the app's own
    // (local) window object, so the header must say "strong local binder".
    // Anything else (a proxy, a different object type) isn't something we
    // can size reliably -- bail out instead of guessing.
    if (type != kBinderTypeBinder) {
        valid = false;
        return;
    }
    // Offset 8 holds `binder` (a pointer to the local object's weak refs).
    //  * 64-bit protocol: an 8-byte field zero-extended from a 32-bit
    //    pointer in a 32-bit process, so the upper half at offset 12 is 0.
    //  * legacy protocol: `binder` is 4 bytes and offset 12 is `cookie`, a
    //    pointer to the local object -- never 0 for a live local binder.
    skip(word3 == 0 ? kFlatBinderObjSize64 : kFlatBinderObjSize32Legacy);
}

inline void FakeParcel::skipFlatObj() {
    if constexpr (sizeof(void*) >= 8) {
        skipFlatObj64();
    } else {
        skipFlatObj32();
    }
}

inline uint32_t* FakeParcel::peekInt32Ref() {
    if (!ensure(sizeof(uint32_t))) return nullptr;
    return (uint32_t*)(data + cur);
}

inline uint32_t FakeParcel::readInt32() {
    const uint32_t* p = peekInt32Ref();
    if (!p) return 0;
    cur += sizeof(uint32_t);
    return *p;
}

inline char16_t* FakeParcel::readString16(uint32_t len) {
    // len+1 for the trailing null u16
    uint64_t bytes = (uint64_t)len * sizeof(char16_t) + sizeof(char16_t);
    // android::Parcel::writeString16() writes through writeInplace(), which
    // always advances mDataPos to a 4-byte boundary (pad_size() in AOSP's
    // Parcel.cpp), even though only `bytes` of it is meaningful data. This
    // is invisible for descriptors with an odd char16 length ((len+1) even)
    // but matters for even-length ones such as
    // "android.app.IActivityTaskManager" (len=32) followed by more reads.
    uint64_t padded = (bytes + 3) & ~(uint64_t)3;
    if (!ensure(padded)) return nullptr;
    char16_t* s = (char16_t*)(data + cur);
    cur += (size_t)padded;
    return s;
}

inline size_t getBinderHeadersLen(int sdk) {
    if (sdk >= 30) return 3 * sizeof(uint32_t);
    else if (sdk == 29) return 2 * sizeof(uint32_t);
    else return 1 * sizeof(uint32_t);
}

bool getMapping(const char* lib, ino_t* inode, dev_t* dev);

// Reads a static int field off an already-resolved class (callers look the
// class up once with FindClass() and reuse it across fields -- FindClass()
// is a full classloader lookup, not a cheap pointer compare).
// cls_name_for_log is only used in log lines. With `quiet` set, a missing
// class or field is silent: for *optional* transactions that legitimately
// don't exist on every Android version, a miss is the normal case, not an
// error worth a logcat line (and a syscall) in every app process.
// Returns 0 on any failure.
uint32_t getStaticIntFieldJni(JNIEnv* env, jclass cls, const char* field_name, const char* cls_name_for_log,
                              bool quiet = false);

// NOTE: not currently called anywhere in this module (no companion process is
// used - all hooking happens in-process). Kept as a general-purpose utility
// for anyone extending the module with root-companion IPC; bounds/EOF-hardened
// below so it's safe to reach for later.
void companionSendFile(const char* path, int remote_fd);

bool readFullFromFd(int fd, void* buf, off_t size);
