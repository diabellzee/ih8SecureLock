#include <android/log.h>
#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "binder.hpp"
// zygisk.hpp is vendored (upstream, not ours to modify -- see the same
// reasoning in build.yml's cppcheck suppressions). -Werror is enabled in
// Android.mk for our own code; scoping the ignore to just this include
// keeps that guarantee for module.cpp itself while not caring what, if
// anything, -Wall/-Wextra/-Wshadow find in a header we don't control.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wall"
#pragma GCC diagnostic ignored "-Wextra"
#pragma GCC diagnostic ignored "-Wshadow"
#include "zygisk.hpp"
#pragma GCC diagnostic pop

#define LOG_TAG "ih8SecureLock"

// Init-time errors and lifecycle messages. These fire a handful of times per
// process at most, never on the Binder path, so they stay unconditional.
#define LOGE(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[%d] [%s] " fmt, __LINE__, PROC_NAME, ##__VA_ARGS__)
#define LOGI(fmt, ...) \
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d] [%s] " fmt, __LINE__, PROC_NAME, ##__VA_ARGS__)

// Per-event messages from the Binder path ("Bypassed ..."). A secure window
// can be relaid out many times a second, and every __android_log_print() is a
// socket write to logd, so each *kind* of bypass is logged once per process:
// enough to confirm in logcat that the module is doing its job, without
// paying a syscall on every transaction. The flag is checked with a relaxed
// load first so the common already-logged case is a plain read, not an
// atomic read-modify-write on a shared cache line.
#define LOGI_ONCE(flag, fmt, ...)                                                    \
    do {                                                                             \
        if (!__atomic_load_n(&(flag), __ATOMIC_RELAXED) &&                           \
            !__atomic_exchange_n(&(flag), true, __ATOMIC_RELAXED)) {                 \
            LOGI(fmt, ##__VA_ARGS__);                                                \
        }                                                                            \
    } while (0)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define FLAG_SECURE 0x00002000

#define I_WINDOW_SESSION_DESC u"android.view.IWindowSession"
#define I_ACTIVITY_TASKMANAGER_DESC u"android.app.IActivityTaskManager"
#define I_WINDOW_MANAGER_DESC u"android.view.IWindowManager"

// Lowest SDK at which each *optional* transaction is worth probing for.
// Each is deliberately one release below the release the transaction first
// appeared in, for two reasons: (1) preview builds of release N report
// android_get_device_api_level() == N-1 (with a codename), so an exact
// "introduced in N" gate would wrongly exclude beta devices, and (2) it
// keeps feature detection (the JNI field lookup) as the real arbiter if a
// vendor backports a transaction a little early. Below these bounds the
// lookup cannot succeed, so we skip it entirely instead of paying for a
// FindClass()/GetStaticFieldID() that is guaranteed to fail (and to throw
// and clear a NoSuchFieldError) in every app process on every cold start.
//
//   registerScreenCaptureObserver    Android 14 (SDK 34)
//   registerScreenRecordingCallback  Android 15 (SDK 35)
//   relayout2 / relayoutAsync2       Android 17 (SDK 37)
//
// relayout/relayoutAsync are always probed: relayout exists on every
// supported release and relayoutAsync appeared in a 13 QPR, so no clean SDK
// bound exists for it.
constexpr int kMinSdkScreenCaptureObserver = 33;
constexpr int kMinSdkScreenRecordingCallback = 34;
constexpr int kMinSdkRelayout2 = 36;

static int sdk = 0;
// getBinderHeadersLen(sdk) only ever depends on `sdk`, which is fixed once
// at process start -- computed once here instead of per matched transaction.
static uint32_t binderHeadersLen = 0;

// UINT32_MAX (never a real AIDL transaction code -- those run from
// FIRST_CALL_TRANSACTION=1 to LAST_CALL_TRANSACTION=0x00FFFFFF) is the
// "lookup failed / not applicable" sentinel, so the hot path can do a plain
// N-way compare against `code` with no separate failure case.
constexpr uint32_t kNoCode = UINT32_MAX;
static uint32_t relayout_code = kNoCode;
static uint32_t relayoutAsync_code = kNoCode;
// Android 17 (SDK 37): IWindowSession gained relayout2/relayoutAsync2
// alongside relayout/relayoutAsync -- see upstream v9
// (https://github.com/j-hc/ih8SecureLock, PR #11 by @jackyzy823). Upstream's
// own comment already flags them as "maybe removed in the future"; on any
// SDK where they don't exist the lookup sentinels to kNoCode.
static uint32_t relayout2_code = kNoCode;
static uint32_t relayoutAsync2_code = kNoCode;
static uint32_t registerScreenCaptureObserver_code = kNoCode;
// Android 15+ screen-*record*-detection counterpart to
// registerScreenCaptureObserver -- IWindowManager.aidl's
// registerScreenRecordingCallback(IScreenRecordingCallback), which backs the
// public WindowManager#addScreenRecordingCallback() API.
static uint32_t registerScreenRecordingCallback_code = kNoCode;

static const char* PROC_NAME = "";

// "Bypassed ..." already logged for this process? (see LOGI_ONCE)
static bool loggedSecureBypass = false;
static bool loggedScreenshotBypass = false;
static bool loggedRecordingBypass = false;

// getStaticIntFieldJni() returns 0 on lookup failure; 0 is never a code
// transactHook() should match, so remap it to kNoCode once, at init time.
static inline uint32_t toSentinel(uint32_t code) { return code == 0 ? kNoCode : code; }

static jclass findClassOrNull(JNIEnv* env, const char* name) {
    jclass cls = env->FindClass(name);
    if (cls == nullptr) env->ExceptionClear();
    return cls;
}

static bool anyCodeResolved() {
    return relayout_code != kNoCode || relayoutAsync_code != kNoCode || relayout2_code != kNoCode ||
           relayoutAsync2_code != kNoCode || registerScreenCaptureObserver_code != kNoCode ||
           registerScreenRecordingCallback_code != kNoCode;
}

static bool getTransactionCodes(JNIEnv* env) {
    // Each distinct class is resolved once and reused across its field
    // lookups; classes that cannot carry any wanted field on this SDK (see
    // kMinSdk* above) are not looked up at all.
    static const char* const kSessionStub = BINDER_STUB("android/view/IWindowSession");
    static const char* const kAtmStub = BINDER_STUB("android/app/IActivityTaskManager");
    static const char* const kWmStub = BINDER_STUB("android/view/IWindowManager");

    jclass sessionCls = findClassOrNull(env, kSessionStub);
    jclass atmCls = sdk >= kMinSdkScreenCaptureObserver ? findClassOrNull(env, kAtmStub) : nullptr;
    jclass wmCls = sdk >= kMinSdkScreenRecordingCallback ? findClassOrNull(env, kWmStub) : nullptr;

    // `relayout` is the one lookup that must succeed on every supported
    // release, so only its failure is reported; everything else is optional
    // and a miss is silent (see getStaticIntFieldJni's `quiet`).
    relayout_code = toSentinel(getStaticIntFieldJni(env, sessionCls, BINDER_TRSCTN("relayout"), kSessionStub));
    relayoutAsync_code =
        toSentinel(getStaticIntFieldJni(env, sessionCls, BINDER_TRSCTN("relayoutAsync"), kSessionStub, true));
    if (sdk >= kMinSdkRelayout2) {
        relayout2_code = toSentinel(getStaticIntFieldJni(env, sessionCls, BINDER_TRSCTN("relayout2"), kSessionStub, true));
        relayoutAsync2_code =
            toSentinel(getStaticIntFieldJni(env, sessionCls, BINDER_TRSCTN("relayoutAsync2"), kSessionStub, true));
    }
    if (atmCls != nullptr) {
        registerScreenCaptureObserver_code = toSentinel(
            getStaticIntFieldJni(env, atmCls, BINDER_TRSCTN("registerScreenCaptureObserver"), kAtmStub, true));
    }
    if (wmCls != nullptr) {
        registerScreenRecordingCallback_code = toSentinel(
            getStaticIntFieldJni(env, wmCls, BINDER_TRSCTN("registerScreenRecordingCallback"), kWmStub, true));
    }

    if (sessionCls != nullptr) env->DeleteLocalRef(sessionCls);
    if (atmCls != nullptr) env->DeleteLocalRef(atmCls);
    if (wmCls != nullptr) env->DeleteLocalRef(wmCls);

    if (!anyCodeResolved()) {
        LOGE("getTransactionCodes: Could not get any transaction codes (sdk=%d)", sdk);
        return false;
    }
    return true;
}

static int (*transactOrig)(void*, int32_t, uint32_t, void*, void*, uint32_t) = nullptr;

static inline bool isRelayoutCode(uint32_t code) {
    return code == relayout_code || code == relayoutAsync_code || code == relayout2_code ||
           code == relayoutAsync2_code;
}

// Cheap, branch-predictable pre-filter used by the hook: could `code` be
// one of the transactions we care about at all?
static inline bool isCandidateCode(uint32_t code) {
    return isRelayoutCode(code) || code == registerScreenCaptureObserver_code ||
           code == registerScreenRecordingCallback_code;
}

// Clear FLAG_SECURE in the (already descriptor-verified) relayout parcel, in
// place. Every skip/peek below is bounds-checked by FakeParcel; if any ran
// past the end of the buffer (short/unexpected payload, different Android
// version, a 32-bit flat-object size that couldn't be determined) ok() is
// false and nothing is touched.
//
// relayout2/relayoutAsync2 (SDK 37+) are assumed to share this same skip
// sequence up to `flags` -- upstream's own PR design, not something
// independently confirmed against a stable Android 17 AIDL (a bounds check
// cannot catch a reordered-but-same-length payload). Worth confirming on a
// real Android 17 device.
static void stripFlagSecure(FakeParcel& parcel) {
    parcel.skipFlatObj();                              // IWindow flat obj
    if (sdk <= 30) parcel.skip(1 * sizeof(uint32_t));  // seq
    parcel.skip(4 * sizeof(uint32_t));                 // LayoutParams
    parcel.skip(3 * sizeof(uint32_t));                 // requestedWidth, requestedHeight, viewVisibility

    uint32_t* pflags = parcel.peekInt32Ref();
    if (!parcel.ok() || pflags == nullptr) return;
    if (*pflags & FLAG_SECURE) {
        *pflags &= ~static_cast<uint32_t>(FLAG_SECURE);
        LOGI_ONCE(loggedSecureBypass, "Bypassed secure lock");
    }
}

// Slow path. Returns true if the transaction must be swallowed (reported to
// the caller as success without ever reaching system_server); false means
// "forward it", possibly after having edited the parcel in place.
//
// Dispatch is on (code AND interface descriptor) *per branch*, never on code
// alone: transaction codes are numbered per AIDL interface, so two of our
// codes (e.g. IActivityTaskManager's and IWindowManager's) can be
// numerically equal by coincidence. Choosing the branch from the code first
// and only then checking the descriptor would silently skip the bypass for
// whichever interface lost the tie. Every condition below is false-fast, so
// a coincidence just falls through to the next branch.
static bool inspectTransaction(uint32_t code, PParcel* pparcel) {
    if (unlikely(pparcel == nullptr || pparcel->data == nullptr)) return false;

    FakeParcel parcel(pparcel->data, pparcel->data_size);
    parcel.skip(binderHeadersLen);  // header

    const uint32_t descLen = parcel.readInt32();
    const char16_t* desc = parcel.readString16(descLen);
    if (unlikely(!parcel.ok() || desc == nullptr)) return false;

    if (isRelayoutCode(code) && BINDER_DESC_CMP(I_WINDOW_SESSION_DESC, desc, descLen)) {
        stripFlagSecure(parcel);
        return false;
    }
    if (code == registerScreenCaptureObserver_code && BINDER_DESC_CMP(I_ACTIVITY_TASKMANAGER_DESC, desc, descLen)) {
        // early-return from capture listener
        LOGI_ONCE(loggedScreenshotBypass, "Bypassed screenshot listener");
        return true;
    }
    if (code == registerScreenRecordingCallback_code && BINDER_DESC_CMP(I_WINDOW_MANAGER_DESC, desc, descLen)) {
        // registerScreenRecordingCallback(IScreenRecordingCallback) returns
        // boolean (whether recording is active). An untouched, empty reply
        // is correct here, not just convenient: both Parcel.readException()
        // and a boolean AIDL result read compile down to
        // Parcel::readInt32(), which defaults to 0 on underflow rather than
        // throwing. Empty reply -> "no exception" + "false", i.e. exactly
        // the "not being recorded" result we want.
        LOGI_ONCE(loggedRecordingBypass, "Bypassed screen recording listener");
        return true;
    }
    return false;
}

// Kept out of line on purpose: this is where the parsing, the FakeParcel
// locals and the logging calls live. If they were inlined into the hook, the
// compiler would save callee-saved registers and allocate a stack frame in
// the hook's prologue *before* the first compare -- i.e. on every Binder
// transaction in the process, not just the few we care about (measured on
// x86-64 GCC -O2: ~200 instructions with a 6-register save vs. 15 with none
// when split). Kept separate, transactHook() below is six compares and a
// tail call.
__attribute__((noinline)) static int transactSlow(void* self, int32_t handle, uint32_t code, void* pdata, void* preply,
                                                  uint32_t flags) {
    if (inspectTransaction(code, reinterpret_cast<PParcel*>(pdata))) return 0;
    return transactOrig(self, handle, code, pdata, preply, flags);
}

// IPCThreadState::transact is hooked process-wide, so this runs for *every*
// Binder call the app makes. Almost all of them are rejected right here by a
// plain integer compare and forwarded with a tail call: no parsing, no
// dereferencing of the Parcel, no stack frame.
static int transactHook(void* self, int32_t handle, uint32_t code, void* pdata, void* preply, uint32_t flags) {
    if (likely(!isCandidateCode(code))) {
        return transactOrig(self, handle, code, pdata, preply, flags);
    }
    return transactSlow(self, handle, code, pdata, preply, flags);
}

static bool hookBinder(zygisk::Api* api) {
    ino_t inode;
    dev_t dev;
    if (!getMapping("libbinder.so", &inode, &dev)) {
        LOGE("Could not get libbinder");
        return false;
    }

    api->pltHookRegister(dev, inode, "_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j",
                         reinterpret_cast<void*>(&transactHook), reinterpret_cast<void**>(&transactOrig));
    if (!api->pltHookCommit()) {
        LOGE("pltHookCommit failed");
        return false;
    }
    // pltHookCommit() succeeding only means the hook table was committed; it
    // doesn't guarantee the symbol was actually found in libbinder.so on
    // this particular Android build/ABI. If it wasn't, transactOrig is still
    // null and every subsequent transactHook() call would crash the app the
    // instant it does any Binder IPC. Fail closed instead.
    if (!transactOrig) {
        LOGE("transact symbol not resolved, refusing to run unhooked");
        return false;
    }
    return true;
}

static bool run(zygisk::Api* api, JNIEnv* env) {
    sdk = android_get_device_api_level();
    if (sdk <= 0) {
        LOGE("android_get_device_api_level: %d", sdk);
        return false;
    }
    binderHeadersLen = (uint32_t)getBinderHeadersLen(sdk);
    if (!getTransactionCodes(env)) return false;
    if (!hookBinder(api)) return false;
    return true;
}

class ih8SecureLock : public zygisk::ModuleBase {
   public:
    void onLoad(zygisk::Api* api_in, JNIEnv* env_in) override {
        this->api = api_in;
        this->env = env_in;
    }

    // Upstream v10 (PR #13 by @nakoo): honor the Zygisk denylist. For a
    // process on the denylist, Magisk/KernelSU unmounts modules, so we must
    // not hook it and must request an unload of our library up front.
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        (void)args;
        if (api->getFlags() & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        // Denylisted process: DLCLOSE was already requested in
        // preAppSpecialize(); install no hooks (upstream v10).
        if (api->getFlags() & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
            return;
        }

        if (unlikely(args->nice_name == nullptr)) {
            // Nothing to hook without a process name to attribute logs to;
            // bail out rather than pass a null jstring into JNI.
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        PROC_NAME = env->GetStringUTFChars(args->nice_name, nullptr);
        if (unlikely(PROC_NAME == nullptr)) {
            // Out of memory or similar JNI failure; nothing more we can
            // safely do (and nothing left to release).
            PROC_NAME = "";
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        if (!run(api, env)) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            env->ReleaseStringUTFChars(args->nice_name, PROC_NAME);
            PROC_NAME = "";
        } else {
            // Intentionally NOT releasing PROC_NAME here: the module stays
            // resident in this process (DLCLOSE was not requested) and the
            // log macros keep referencing PROC_NAME for the lifetime of the
            // process, so its backing chars must stay alive.
            LOGI("Loaded (sdk=%d, relayout=%d/%d/%d/%d, screenshot=%d, recording=%d)", sdk, (int)relayout_code,
                 (int)relayoutAsync_code, (int)relayout2_code, (int)relayoutAsync2_code,
                 (int)registerScreenCaptureObserver_code, (int)registerScreenRecordingCallback_code);
        }
    }

   private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(ih8SecureLock)
