// callout.c - WFP ALE_CONNECT_REDIRECT user-mode callout DLL
// Redirects target TCP connections to local SOCKS5 forwarder

#pragma comment(lib, "fwpuclnt")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "advapi32")

#include <windows.h>
#include <fwpmu.h>
#include <mstcpip.h>
#include <winsock2.h>
#include <ws2ipdef.h>

// GUIDs
// {C9A8F1E0-4B1A-4A9D-8C1A-2F0E9D84B1A9}
const GUID CALLOUT_GUID = {
    0xc9a8f1e0, 0x4b1a, 0x4a9d, {0x8c, 0x1a, 0x2f, 0x0e, 0x9d, 0x84, 0xb1, 0xa9}
};
// {D9B8F2E1-5C2B-4B9E-9D2A-3F1E0A84C2B9}
const GUID SUBLAYER_GUID = {
    0xd9b8f2e1, 0x5c2b, 0x4b9e, {0x9d, 0x2a, 0x3f, 0x1e, 0x0a, 0x84, 0xc2, 0xb9}
};

#define SHM_ORIG_NAME  L"Local\\MRPORT_ORIG_DST"
#define SHM_TARGET_NAME L"Local\\MRPORT_TARGETS"
#define SHM_SIZE 65536
#define MAX_TARGETS 64

static HANDLE g_engine = NULL;
static HANDLE g_shmOrig = NULL, g_shmTargets = NULL;
static BYTE* g_origView = NULL, *g_targetView = NULL;

// FWPS_CONNECT_REQUEST0 - user-mode version (from Windows SDK)
typedef struct _MRPORT_CONNECT_REQUEST {
    SOCKADDR* localAddress;
    SOCKADDR* remoteAddress;
    USHORT localPort;
    USHORT remotePort;
    UINT64 portReservationToken;
    USHORT localAddressLength;
    USHORT remoteAddressLength;
} MRPORT_CONNECT_REQUEST;

static BOOL IsTargetIp(ULONG ip) {
    if (!g_targetView) return FALSE;
    LONG count;
    memcpy(&count, g_targetView, 4);
    if (count < 0) count = 0;
    if (count > MAX_TARGETS) count = MAX_TARGETS;
    for (LONG i = 0; i < count; i++) {
        ULONG target;
        memcpy(&target, g_targetView + 4 + i * 4, 4);
        if (ip == target) return TRUE;
    }
    return FALSE;
}

static void StoreOrigDst(USHORT localPort, ULONG origIp, USHORT origPort) {
    if (!g_origView) return;
    USHORT count;
    memcpy(&count, g_origView, 2);
    if (count >= 4000) count = 0;
    ULONG offset = 2 + count * 8;
    memcpy(g_origView + offset, &localPort, 2);
    memcpy(g_origView + offset + 2, &origIp, 4);
    memcpy(g_origView + offset + 6, &origPort, 2);
    count++;
    memcpy(g_origView, &count, 2);
}

void NTAPI ClassifyFn(
    const FWPS_INCOMING_VALUES* inFixed,
    const FWPS_INCOMING_METADATA_VALUES* inMeta,
    void* layerData, const void* context,
    const FWPS_FILTER* filter, UINT64 flow,
    FWPS_CLASSIFY_OUT* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    if (!layerData || !inFixed || inFixed->layerId != FWPM_LAYER_ALE_CONNECT_REDIRECT_V4)
        return;

    MRPORT_CONNECT_REQUEST* req = (MRPORT_CONNECT_REQUEST*)layerData;
    if (!req->remoteAddress) return;

    SOCKADDR_IN* remote = (SOCKADDR_IN*)req->remoteAddress;
    ULONG ip = remote->sin_addr.S_un.S_addr;
    USHORT port = remote->sin_port;
    USHORT localPort = req->localPort;

    // Check 127.0.0.1:80 (always proxy)
    if (ip == htonl(0x0100007F) && ntohs(port) == 80) {
        ULONG fakeOrig = htonl(0x0100007F); // 127.0.0.1
        StoreOrigDst(localPort, fakeOrig, port);
        return; // Let it connect to 127.0.0.1:80 normally; local listener handles it
    }

    // Check target IPs
    if (IsTargetIp(ip)) {
        StoreOrigDst(localPort, ip, port);
        // Redirect to local proxy
        remote->sin_addr.S_un.S_addr = htonl(0x0100007F); // 127.0.0.1
        remote->sin_port = htons(21539);
        remote->sin_family = AF_INET;
    }
}

NTSTATUS NTAPI NotifyFn(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER* filter) {
    return STATUS_SUCCESS;
}

static BOOL CreateSharedMemory() {
    g_shmOrig = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHM_SIZE, SHM_ORIG_NAME);
    if (!g_shmOrig) return FALSE;
    g_origView = (BYTE*)MapViewOfFile(g_shmOrig, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
    if (!g_origView) return FALSE;
    memset(g_origView, 0, SHM_SIZE);

    g_shmTargets = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 256, SHM_TARGET_NAME);
    if (!g_shmTargets) return FALSE;
    g_targetView = (BYTE*)MapViewOfFile(g_shmTargets, FILE_MAP_ALL_ACCESS, 0, 0, 256);
    if (!g_targetView) return FALSE;
    memset(g_targetView, 0, 256);
    return TRUE;
}

__declspec(dllexport) BOOL WINAPI Initialize() {
    if (!CreateSharedMemory()) return FALSE;

    HANDLE engine = NULL;
    FWPM_SESSION session = { .flags = FWPM_SESSION_FLAG_DYNAMIC };
    if (FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine)) {
        return FALSE;
    }
    g_engine = engine;

    // Register callout
    FWPM_CALLOUT callout = {
        .calloutKey = CALLOUT_GUID,
        .displayData = { .name = L"MRPORT Redirect", .description = L"Redirect to proxy" },
        .applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        .flags = 0
    };
    if (FwpmCalloutAdd(engine, &callout, NULL, NULL)) {
        // Already exists - OK
    }

    // Add sublayer
    FWPM_SUBLAYER sublayer = {
        .subLayerKey = SUBLAYER_GUID,
        .displayData = { .name = L"MRPORT Sublayer", .description = L"" },
        .weight = 0x100
    };
    FwpmSubLayerAdd(engine, &sublayer, NULL);

    return TRUE;
}

__declspec(dllexport) BOOL WINAPI AddFilter(ULONG targetIp, USHORT port) {
    if (!g_engine) return FALSE;

    FWPM_FILTER filter = {
        .subLayerKey = SUBLAYER_GUID,
        .layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        .displayData = { .name = L"MRPORT Filter", .description = L"" },
        .action = { .type = FWP_ACTION_CALLOUT_TERMINATING, .calloutKey = CALLOUT_GUID },
        .numFilterConditions = 2
    };

    FWPM_FILTER_CONDITION conds[2] = {
        { .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
          .matchType = FWP_MATCH_EQUAL,
          .conditionValue = { .type = FWP_UINT32, .uint32 = targetIp } },
        { .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
          .matchType = FWP_MATCH_EQUAL,
          .conditionValue = { .type = FWP_UINT8, .uint8 = IPPROTO_TCP } }
    };

    int numConds = 2;
    FWPM_FILTER_CONDITION conds3[3];
    if (port != 0) {
        memcpy(conds3, conds, sizeof(conds));
        conds3[2] = (FWPM_FILTER_CONDITION){
            .fieldKey = FWPM_CONDITION_IP_REMOTE_PORT,
            .matchType = FWP_MATCH_EQUAL,
            .conditionValue = { .type = FWP_UINT16, .uint16 = htons(port) }
        };
        numConds = 3;
        filter.filterCondition = conds3;
    } else {
        filter.filterCondition = conds;
    }

    filter.numFilterConditions = numConds;
    return FwpmFilterAdd(g_engine, &filter, NULL, NULL) == 0;
}

__declspec(dllexport) ULONG WINAPI GetTargetCount() {
    if (!g_targetView) return 0;
    ULONG count;
    memcpy(&count, g_targetView, 4);
    return count;
}

__declspec(dllexport) BOOL WINAPI SetTargets(ULONG* ips, ULONG count) {
    if (!g_targetView || count > MAX_TARGETS) return FALSE;
    memcpy(g_targetView, &count, 4);
    for (ULONG i = 0; i < count; i++)
        memcpy(g_targetView + 4 + i * 4, &ips[i], 4);
    return TRUE;
}

__declspec(dllexport) BOOL WINAPI ReadOrigDst(USHORT localPort, ULONG* outIp, USHORT* outPort) {
    if (!g_origView) return FALSE;
    USHORT count;
    memcpy(&count, g_origView, 2);
    for (USHORT i = 0; i < count; i++) {
        ULONG offset = 2 + i * 8;
        USHORT storedPort;
        memcpy(&storedPort, g_origView + offset, 2);
        if (storedPort == localPort) {
            memcpy(outIp, g_origView + offset + 2, 4);
            memcpy(outPort, g_origView + offset + 6, 2);
            return TRUE;
        }
    }
    return FALSE;
}

__declspec(dllexport) void WINAPI Shutdown() {
    if (g_engine) FwpmEngineClose(g_engine);
    g_engine = NULL;
    if (g_targetView) { UnmapViewOfFile(g_targetView); g_targetView = NULL; }
    if (g_shmTargets) { CloseHandle(g_shmTargets); g_shmTargets = NULL; }
    if (g_origView) { UnmapViewOfFile(g_origView); g_origView = NULL; }
    if (g_shmOrig) { CloseHandle(g_shmOrig); g_shmOrig = NULL; }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) { return TRUE; }
