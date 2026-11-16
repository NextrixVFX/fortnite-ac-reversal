/*
 * eac_emu_stub.c
 *
 * Minimum-viable stub replacement for the EAC client DLL. Matches the
 * public EOS Anti-Cheat Client interface. All functions return success
 * values and do no work.
 *
 * Build:
 *   cl /LD /O2 eac_emu_stub.c /Fe:EasyAntiCheat_x64.dll \
 *      /link /DEF:eac_emu_stub.def
 *
 * The .def file lists exports in the order the target build of EAC
 * uses (ordinals must match the game's IAT). Lift the ordinal table
 * from the real EAC_x64.dll via CFF Explorer.
 *
 * See ../../docs/13-eac-emulation.md for full context.
 */

#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* --- types from EOS SDK anti-cheat client public headers --- */

typedef int32_t EOS_EResult;
#define EOS_SUCCESS       ((EOS_EResult)0)
#define EOS_INVALID_PARAM ((EOS_EResult)1)
#define EOS_NOT_FOUND     ((EOS_EResult)2)

typedef void* EOS_HAntiCheatClient;
typedef uint64_t EOS_AntiCheatCommon_ClientHandle;

typedef enum {
    EOS_ACCCS_Disconnected  = 0,
    EOS_ACCCS_Connected     = 1,
    EOS_ACCCS_ConnectFailed = 2,
    EOS_ACCCS_Protected     = 3,
    EOS_ACCCS_Error         = 4,
} EOS_EAntiCheatClientSessionState;

typedef enum {
    EOS_ACCM_Peer   = 0,
    EOS_ACCM_Server = 1,
} EOS_EAntiCheatClientMode;

typedef struct {
    int32_t ApiVersion;
    EOS_EAntiCheatClientSessionState NewSessionState;
    const char* ServerAddress;
} EOS_AntiCheatClient_OnClientIntegrityViolatedCallbackInfo;

typedef void (*EOS_AntiCheatClient_OnClientIntegrityViolatedCallback)(
    const void* Data);

typedef struct {
    int32_t ApiVersion;
    EOS_AntiCheatCommon_ClientHandle ClientHandle;
} EOS_AntiCheatClient_PollStatusOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_AntiCheatCommon_ClientHandle ClientHandle;
    const void* Data;
    uint32_t DataLengthBytes;
} EOS_AntiCheatClient_ReceiveMessageOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_AntiCheatCommon_ClientHandle ClientHandle;
} EOS_AntiCheatClient_RegisterPeerOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_EAntiCheatClientMode Mode;
} EOS_AntiCheatClient_BeginSessionOptions;

/* --- stub state --- */

static struct {
    EOS_AntiCheatClient_OnClientIntegrityViolatedCallback integrity_cb;
    const void* integrity_cb_ctx;
    int session_active;
    EOS_EAntiCheatClientSessionState session_state;
    EOS_AntiCheatCommon_ClientHandle next_handle;
} g = { 0 };

/* --- EOS exports --- */

__declspec(dllexport) EOS_HAntiCheatClient
EOS_Platform_GetAntiCheatClientInterface(void* platform)
{
    (void)platform;
    /* Return anything non-null; game stores and uses as opaque. */
    return (EOS_HAntiCheatClient)(uintptr_t)0xEAC1DEADBEEFEAC1ULL;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_BeginSession(EOS_HAntiCheatClient h,
                                 const EOS_AntiCheatClient_BeginSessionOptions* opts)
{
    (void)h; (void)opts;
    g.session_active = 1;
    g.session_state = EOS_ACCCS_Protected;
    g.next_handle = 1;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_EndSession(EOS_HAntiCheatClient h, const void* opts)
{
    (void)h; (void)opts;
    g.session_active = 0;
    g.session_state = EOS_ACCCS_Disconnected;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_PollStatus(EOS_HAntiCheatClient h,
                               const EOS_AntiCheatClient_PollStatusOptions* opts,
                               void* out_msg,
                               uint32_t* out_msg_sz)
{
    (void)h; (void)opts;
    if (out_msg_sz) *out_msg_sz = 0;
    (void)out_msg;
    /* No outgoing messages because the stub is not anti-cheating. */
    return EOS_NOT_FOUND;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_ReceiveMessageFromServer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_ReceiveMessageOptions* opts)
{
    (void)h; (void)opts;
    /* Accept whatever the server sends. */
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_RegisterPeer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_RegisterPeerOptions* opts)
{
    (void)h; (void)opts;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_UnregisterPeer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_RegisterPeerOptions* opts)
{
    (void)h; (void)opts;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_ReceiveMessageFromPeer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_ReceiveMessageOptions* opts)
{
    (void)h; (void)opts;
    return EOS_SUCCESS;
}

/* integrity callback registration */
__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_AddNotifyClientIntegrityViolated(
    EOS_HAntiCheatClient h,
    const void* options,
    const void* ctx,
    EOS_AntiCheatClient_OnClientIntegrityViolatedCallback cb)
{
    (void)h; (void)options;
    g.integrity_cb = cb;
    g.integrity_cb_ctx = ctx;
    /* Return a notification id; game stores for later Remove. */
    return (EOS_EResult)0x1234;
}

__declspec(dllexport) void
EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated(
    EOS_HAntiCheatClient h,
    uint32_t notification_id)
{
    (void)h; (void)notification_id;
    g.integrity_cb = NULL;
    g.integrity_cb_ctx = NULL;
}

/*
 * Classic EAC compatibility exports.
 *
 * Names and ordinals rotate per version. For a real drop-in against
 * a specific Fortnite build, replace the .def ordinals with ones
 * lifted from CFF Explorer against the real EasyAntiCheat_x64.dll
 * that ships with your target build.
 */

__declspec(dllexport) int32_t
EAC_Client_Init(void* ctx)
{
    (void)ctx;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_Shutdown(void* ctx)
{
    (void)ctx;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_PollStatus(void* ctx, void* out)
{
    (void)ctx; (void)out;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_RegisterPeer(void* ctx, uint64_t pid, void* opts)
{
    (void)ctx; (void)pid; (void)opts;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_UnregisterPeer(void* ctx, uint64_t pid)
{
    (void)ctx; (void)pid;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_ReceiveMessage(void* ctx, const void* data, uint32_t len)
{
    (void)ctx; (void)data; (void)len;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_GetProtectedData(void* ctx, void* out, uint32_t* len)
{
    (void)ctx;
    if (len) *len = 0;
    (void)out;
    return 0;
}

/* DllMain */
BOOL WINAPI
DllMain(HINSTANCE h, DWORD why, LPVOID rsv)
{
    (void)rsv;
    if (why == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
