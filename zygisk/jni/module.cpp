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

#define LOGD(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, "ih8SecureLock", "[%d] [%s] " fmt, __LINE__, PROC_NAME, ##__VA_ARGS__)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define FLAG_SECURE 0x00002000

#define I_WINDOW_SESSION_DESC u"android.view.IWindowSession"
#define I_ACTIVITY_TASKMANAGER_DESC u"android.app.IActivityTaskManager"
#define I_WINDOW_MANAGER_DESC u"android.view.IWindowManager"

static int sdk = 0;
// getBinderHeadersLen(sdk) only ever depends on `sdk`, which is fixed once
// at process start -- computed once here instead of on every matched
// transaction in transactHook() below.
static uint32_t binderHeadersLen = 0;
// UINT32_MAX (never a real AIDL transaction code -- those run from
// FIRST_CALL_TRANSACTION=1 to LAST_CALL_TRANSACTION=0x00FFFFFF) is the
// "lookup failed / not applicable" sentinel, not 0. This lets
// transactHook()'s hot-path fast-reject do a plain N-way compare against
// `code` with no separate failure case to special-case -- see below.
static uint32_t relayout_code = UINT32_MAX;
static uint32_t relayoutAsync_code = UINT32_MAX;
// Android 17 (SDK 37): IWindowSession gained relayout2/relayoutAsync2
// alongside the existing relayout/relayoutAsync -- see upstream v9
// (https://github.com/j-hc/ih8SecureLock, PR #11 by @jackyzy823) and
// https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/java/android/view/IWindowSession.aidl#93.
// Android 17 was still in beta when this was first written and that AIDL has
// historically been reshuffled across releases (relayout itself gained a
// new lastSyncSeqId parameter at some point, for instance) -- upstream's
// own comment already flags relayout2 as "maybe removed in the future".
// On any SDK where it doesn't exist the lookup below sentinels to
// UINT32_MAX exactly like every other optional transaction code here, so
// this is safe to probe for unconditionally without an explicit SDK gate.
static uint32_t relayout2_code = UINT32_MAX;
static uint32_t relayoutAsync2_code = UINT32_MAX;
static uint32_t registerScreenCaptureObserver_code = UINT32_MAX;
// Android 15+ (VANILLA_ICE_CREAM) screen-*record*-detection counterpart to
// registerScreenCaptureObserver above -- see IWindowManager.aidl's
// registerScreenRecordingCallback(IScreenRecordingCallback), which backs the
// public WindowManager#addScreenRecordingCallback() API. On pre-15 devices
// android.view.IWindowManager$Stub simply has no
// TRANSACTION_registerScreenRecordingCallback field, so the lookup below
// fails exactly like any other unavailable transaction and this sentinels
// to UINT32_MAX -- safe to probe for unconditionally, no explicit SDK-gate
// needed (mirrors how registerScreenCaptureObserver already degrades on
// pre-14 devices).
static uint32_t registerScreenRecordingCallback_code = UINT32_MAX;

static const char* PROC_NAME = "";

// getStaticIntFieldJni() returns 0 both on genuine lookup failure and on
// the (never-happens-in-practice) case of an actual field value of 0;
// either way 0 is not a code transactHook() should ever match against, so
// remap it to the UINT32_MAX sentinel right here, once at init time,
// rather than re-checking `code == 0` on every single Binder transaction
// in the process for the rest of its life.
static inline uint32_t toSentinel(uint32_t code) { return code == 0 ? UINT32_MAX : code; }

static bool getTransactionCodes(JNIEnv* env) {
    // 4 of the 6 lookups below (relayout/relayoutAsync/relayout2/
    // relayoutAsync2) target the *same* class, IWindowSession$Stub. The
    // previous version called getStaticIntFieldJni(env, "...IWindowSession",
    // ...) separately per field, so FindClass() -- a full classloader
    // lookup, not a cheap pointer compare -- ran 4 times over for one
    // class. This runs once per app process (postAppSpecialize, at zygote
    // fork time), so the win is small in absolute terms, but it's paid on
    // *every* app cold start on the device, across every app the module
    // hooks. Resolving each distinct class once and reusing the jclass
    // across its field lookups cuts this from 6 FindClass calls to 3.
    jclass windowSessionCls = env->FindClass(BINDER_STUB("android/view/IWindowSession"));
    if (windowSessionCls == nullptr) env->ExceptionClear();
    jclass activityTaskManagerCls = env->FindClass(BINDER_STUB("android/app/IActivityTaskManager"));
    if (activityTaskManagerCls == nullptr) env->ExceptionClear();
    jclass windowManagerCls = env->FindClass(BINDER_STUB("android/view/IWindowManager"));
    if (windowManagerCls == nullptr) env->ExceptionClear();

    relayout_code = toSentinel(getStaticIntFieldJni(env, windowSessionCls, BINDER_TRSCTN("relayout"),
                                                     "android/view/IWindowSession$Stub"));
    relayoutAsync_code = toSentinel(getStaticIntFieldJni(env, windowSessionCls, BINDER_TRSCTN("relayoutAsync"),
                                                          "android/view/IWindowSession$Stub"));
    relayout2_code = toSentinel(getStaticIntFieldJni(env, windowSessionCls, BINDER_TRSCTN("relayout2"),
                                                      "android/view/IWindowSession$Stub"));
    relayoutAsync2_code = toSentinel(getStaticIntFieldJni(env, windowSessionCls, BINDER_TRSCTN("relayoutAsync2"),
                                                           "android/view/IWindowSession$Stub"));
    registerScreenCaptureObserver_code = toSentinel(
        getStaticIntFieldJni(env, activityTaskManagerCls, BINDER_TRSCTN("registerScreenCaptureObserver"),
                              "android/app/IActivityTaskManager$Stub"));
    registerScreenRecordingCallback_code = toSentinel(
        getStaticIntFieldJni(env, windowManagerCls, BINDER_TRSCTN("registerScreenRecordingCallback"),
                              "android/view/IWindowManager$Stub"));

    if (windowSessionCls != nullptr) env->DeleteLocalRef(windowSessionCls);
    if (activityTaskManagerCls != nullptr) env->DeleteLocalRef(activityTaskManagerCls);
    if (windowManagerCls != nullptr) env->DeleteLocalRef(windowManagerCls);

    if (registerScreenCaptureObserver_code == UINT32_MAX && relayoutAsync_code == UINT32_MAX &&
        relayout_code == UINT32_MAX && relayoutAsync2_code == UINT32_MAX && relayout2_code == UINT32_MAX &&
        registerScreenRecordingCallback_code == UINT32_MAX) {
        LOGD("ERROR getTransactionCodes: Could not get any transaction codes");
        return false;
    }
    return true;
}

int (*transactOrig)(void*, int32_t, uint32_t, void*, void*, uint32_t) = nullptr;

int transactHook(void* self, int32_t handle, uint32_t code, void* pdata, void* preply, uint32_t flags) {
    // Hot-path fast-reject: IPCThreadState::transact is hooked process-wide,
    // so this runs for *every* Binder call the app makes, not just the two
    // or three we care about. The original code unconditionally parsed the
    // parcel header + interface descriptor before ever looking at `code`,
    // which means every unrelated transaction paid for work whose result
    // was thrown away. A plain integer compare is essentially free and
    // rejects the overwhelming majority of calls immediately.
    //
    // A failed transaction-code lookup sentinels to UINT32_MAX (see
    // toSentinel() above), which real AIDL transaction codes can never
    // equal (they run 1..0x00FFFFFF) -- so a failed lookup simply never
    // matches any real `code` here, with no separate `code == 0` check
    // needed on this per-call path.
    if (likely(code != relayout_code && code != relayoutAsync_code && code != relayout2_code &&
               code != relayoutAsync2_code && code != registerScreenCaptureObserver_code &&
               code != registerScreenRecordingCallback_code)) {
        return transactOrig(self, handle, code, pdata, preply, flags);
    }

    auto pparcel = reinterpret_cast<PParcel*>(pdata);
    if (unlikely(pparcel == nullptr || pparcel->data == nullptr)) {
        return transactOrig(self, handle, code, pdata, preply, flags);
    }

    auto parcel = FakeParcel(pparcel->data, pparcel->data_size);
    parcel.skip(binderHeadersLen);  // header

    auto descLen = parcel.readInt32();
    auto desc = parcel.readString16(descLen);

    // Every skip/read above is bounds-checked internally by FakeParcel; if
    // any of them ran past the end of the parcel (unexpected/short buffer,
    // different Android version, etc.) `ok()` is false and `desc` is null.
    // Falling back to the real transact is always safe -- we just don't get
    // to touch FLAG_SECURE or the capture-observer call for this one call.
    if (unlikely(!parcel.ok() || desc == nullptr)) {
        return transactOrig(self, handle, code, pdata, preply, flags);
    }

    // Note on the branching below: transaction codes are numbered
    // per-interface (each AIDL interface starts its own numbering at
    // FIRST_CALL_TRANSACTION=1), so it's entirely normal for e.g.
    // relayout_code and registerScreenRecordingCallback_code to end up
    // numerically equal by coincidence -- they come from two unrelated
    // interfaces (IWindowSession vs IWindowManager). The interface
    // descriptor comparison inside each branch is what actually
    // disambiguates; if `code` matches a branch but the descriptor doesn't,
    // that branch's inner `if` is simply false and we fall through to the
    // ordinary transactOrig() at the bottom, i.e. worst case on a coincidental
    // code collision is "no bypass applied for this call", never a crash.
    if (code == relayout_code || code == relayoutAsync_code || code == relayout2_code ||
        code == relayoutAsync2_code) {
        if (BINDER_DESC_CMP(I_WINDOW_SESSION_DESC, desc, descLen)) {
            // remove FLAG_SECURE mask
            //
            // relayout2/relayoutAsync2 (SDK 37+) are assumed to share this
            // same skip sequence up to `flags` -- that's upstream's own PR
            // design (see the relayout2_code comment above), not something
            // independently re-derived here: Android 17 was still in beta
            // as of this writing and the exact relayout2 parameter layout
            // wasn't something a fixed AOSP tag could confirm with
            // certainty. If that assumption turns out wrong on a real
            // device, the bounds-checked peekInt32Ref()/ok() guard below
            // fails closed (no bypass applied) rather than corrupting an
            // unrelated field silently in-bounds -- but only for a
            // *shorter* relayout2 payload; a *reordered-but-same-length*
            // one wouldn't be caught by a bounds check at all. Worth
            // confirming against a real Android 17 device once out of beta.

            parcel.skipFlatObj();                              // IWindow flat obj
            if (sdk <= 30) parcel.skip(1 * sizeof(uint32_t));  // seq
            parcel.skip(4 * sizeof(uint32_t));                 // LayoutParams
            parcel.skip(3 * sizeof(uint32_t));  // requestedWidth, requestedHeight, viewVisibility

            auto* pflags = parcel.peekInt32Ref();
            if (parcel.ok() && pflags != nullptr && (*pflags & FLAG_SECURE)) {
                *pflags &= ~FLAG_SECURE;
                LOGD("Bypassed secure lock");
            }
        }
    } else if (code == registerScreenCaptureObserver_code) {
        if (BINDER_DESC_CMP(I_ACTIVITY_TASKMANAGER_DESC, desc, descLen)) {
            // early-return from capture listener
            LOGD("Bypassed screenshot listener");
            return 0;
        }
    } else {  // code == registerScreenRecordingCallback_code
        if (BINDER_DESC_CMP(I_WINDOW_MANAGER_DESC, desc, descLen)) {
            // registerScreenRecordingCallback(IScreenRecordingCallback)
            // returns boolean (whether recording is active). An untouched,
            // empty reply is correct here, not just convenient: both
            // Parcel.readException() and a boolean AIDL result read compile
            // down to Parcel::readInt32(), which is documented to default
            // to 0 on underflow rather than throw (readAligned<T>() in
            // frameworks/native/libs/binder/Parcel.cpp). Empty reply -> "no
            // exception" + "false", i.e. exactly the "not being recorded"
            // result we want -- no reply-parcel writing needed.
            LOGD("Bypassed screen recording listener");
            return 0;
        }
    }
    return transactOrig(self, handle, code, pdata, preply, flags);
}

static bool hookBinder(zygisk::Api* api) {
    ino_t inode;
    dev_t dev;
    if (!getMapping("libbinder.so", &inode, &dev)) {
        LOGD("ERROR: Could not get libbinder");
        return false;
    }

    api->pltHookRegister(dev, inode, "_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j",
                         reinterpret_cast<void*>(&transactHook), reinterpret_cast<void**>(&transactOrig));
    if (!api->pltHookCommit()) {
        LOGD("ERROR: pltHookCommit");
        return false;
    }
    // pltHookCommit() succeeding only means the hook table was committed; it
    // doesn't guarantee the symbol was actually found in libbinder.so on
    // this particular Android build/ABI. If it wasn't, transactOrig is still
    // null and every subsequent transactHook() call would crash the app the
    // instant it does any Binder IPC. Fail closed instead.
    if (!transactOrig) {
        LOGD("ERROR: transact symbol not resolved, refusing to run unhooked");
        return false;
    }
    return true;
}

static bool run(zygisk::Api* api, JNIEnv* env) {
    sdk = android_get_device_api_level();
    if (sdk <= 0) {
        LOGD("ERROR android_get_device_api_level: %d", sdk);
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
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        if (!run(api, env)) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            env->ReleaseStringUTFChars(args->nice_name, PROC_NAME);
            PROC_NAME = "";
        } else {
            // Intentionally NOT releasing PROC_NAME here: the module stays
            // resident in this process (DLCLOSE was not requested) and
            // transactHook()'s LOGD keeps referencing PROC_NAME for the
            // lifetime of the process, so its backing chars must stay alive.
            LOGD("Loaded");
        }
    }

   private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(ih8SecureLock)
