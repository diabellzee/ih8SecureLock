#include "binder.hpp"

#include <android/log.h>
#include <asm-generic/fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOGD(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, "ih8SecureLock", "[%d] " fmt, __LINE__, ##__VA_ARGS__)

namespace {

struct MappingSearch {
    const char* lib_name;
    size_t lib_name_len;
    ino_t inode;
    dev_t dev;
    bool found;
};

// Called once per loaded module (shared object or the main executable) by
// dl_iterate_phdr(), courtesy of the dynamic linker's own bookkeeping --
// not by scraping /proc/self/maps text. This sidesteps the previous
// approach's two structural weaknesses: (1) a library backed by a pathname
// containing whitespace would break the %*s-based field split, and (2) each
// shared object shows up as *several* /proc/self/maps lines (text r-xp,
// rodata r--p, data rw-p, ...) all needing the same dev/inode, which is why
// the old code additionally had to filter on flags[2]=='x' to land on one
// specific line. Here the linker already hands us one entry per module, so
// neither problem exists: dlpi_name is the exact path (no need to search
// for the library name as a substring of a larger line), and dev/inode is
// pulled straight from stat() on that path -- the same value every segment
// of that module would resolve to, obtained without caring which segment.
int mappingCallback(dl_phdr_info* info, size_t /*size*/, void* data) {
    auto* ctx = static_cast<MappingSearch*>(data);
    // The main executable (and occasionally the VDSO/linker itself) reports
    // an empty dlpi_name; nothing to match against, so skip rather than let
    // the length check below underflow.
    if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') return 0;

    size_t path_len = strlen(info->dlpi_name);
    if (path_len < ctx->lib_name_len) return 0;
    // Suffix match on the full path, e.g. "/apex/.../lib64/libbinder.so"
    // ends with "libbinder.so" -- same matching semantics the old
    // maps-parsing version used, just against a clean path string instead
    // of an arbitrary slice of a text line.
    size_t match_start = path_len - ctx->lib_name_len;
    if (memcmp(info->dlpi_name + match_start, ctx->lib_name, ctx->lib_name_len) != 0) {
        return 0;
    }
    // Beyond matching the tail characters, require them to actually start a
    // path *component*: either the whole path is exactly lib_name, or the
    // byte right before the match is '/'. Without this, a module named
    // e.g. "vendor_liblibbinder.so" would satisfy a plain suffix check even
    // though it isn't the library being searched for -- same class of bug
    // a real string-vs-string equality check on a basename would avoid,
    // here done cheaply without a separate basename() call.
    if (match_start != 0 && info->dlpi_name[match_start - 1] != '/') return 0;

    struct stat st;
    if (stat(info->dlpi_name, &st) != 0) {
        // Matched by name but the path no longer resolves (e.g. the file
        // was unlinked out from under a still-mapped inode). Keep looking
        // rather than report a stale/zeroed dev+inode as if it were valid.
        return 0;
    }
    ctx->inode = st.st_ino;
    ctx->dev = st.st_dev;
    ctx->found = true;
    return 1;  // non-zero stops dl_iterate_phdr's iteration
}

}  // namespace

bool getMapping(const char* lib_name, ino_t* inode, dev_t* dev) {
    MappingSearch ctx{lib_name, strlen(lib_name), 0, 0, false};
    dl_iterate_phdr(mappingCallback, &ctx);
    if (!ctx.found) return false;
    *inode = ctx.inode;
    *dev = ctx.dev;
    return true;
}

uint32_t getStaticIntFieldJni(JNIEnv* env, jclass cls, const char* field_name, const char* cls_name_for_log) {
    if (cls == nullptr) {
        // Caller already tried FindClass and it failed (and already cleared
        // the resulting exception) -- nothing more to look up.
        LOGD("ERROR getStaticIntFieldJni: Could not get class '%s'", cls_name_for_log);
        return 0;
    }
    jfieldID field = env->GetStaticFieldID(cls, field_name, "I");
    if (field == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get field %s.%s", cls_name_for_log, field_name);
        return 0;
    }
    jint val = env->GetStaticIntField(cls, field);
    return val;
}

uint32_t getStaticIntFieldJni(JNIEnv* env, const char* cls_name, const char* field_name) {
    jclass cls = env->FindClass(cls_name);
    if (cls == nullptr) env->ExceptionClear();
    uint32_t val = getStaticIntFieldJni(env, cls, field_name, cls_name);
    if (cls != nullptr) env->DeleteLocalRef(cls);
    return val;
}

void companionSendFile(const char* path, int remote_fd) {
    off_t size = 0;
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        LOGD("ERROR open: %s", strerror(errno));
    } else {
        struct stat st;
        if (fstat(fd, &st) == -1) {
            LOGD("ERROR fstat: %s", strerror(errno));
        } else {
            size = st.st_size;
        }
    }

    // Protocol: always send the size first (0 on any failure above) so the
    // remote side has a well-defined framing to read, even on the error path.
    if (write(remote_fd, &size, sizeof(size)) < 0) {
        LOGD("ERROR write: %s", strerror(errno));
        size = 0;
    }
    // fd 0 is a perfectly valid descriptor (open() can return it if fd 0
    // happened to be free); the original `fd > 0` check would leak it.
    if (fd >= 0) {
        if (size > 0 && sendfile(remote_fd, fd, NULL, size) < 0) {
            LOGD("ERROR sendfile: %s", strerror(errno));
        }
        close(fd);
    }
}

bool readFullFromFd(int fd, void* buf, off_t size) {
    off_t size_read = 0;
    while (size_read < size) {
        ssize_t ret = read(fd, reinterpret_cast<char*>(buf) + size_read, size - size_read);
        if (ret < 0) {
            if (errno == EINTR) continue;  // interrupted, safe to retry
            LOGD("ERROR read: %s", strerror(errno));
            return false;
        } else if (ret == 0) {
            // EOF / peer closed before delivering the promised `size` bytes.
            // The original code treated this as "add zero and loop again",
            // which spins the CPU forever instead of failing.
            LOGD("ERROR read: unexpected EOF (%ld/%ld bytes)", (long)size_read, (long)size);
            return false;
        } else {
            size_read += ret;
        }
    }
    return true;
}
