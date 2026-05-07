// callout.c - WFP ALE_CONNECT_REDIRECT user-mode callout DLL
// Compiled as C++ (/TP) for MSVC compatibility

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <fwpmu.h>

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
    if (count < 0 || count > MAX_TARGETS) count = 0;
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

    // 127.0.0.1:80 - always proxy (let local listener handle)
    if (ip == htonl(0x0100007F) && ntohs(port) == 80) {
        StoreOrigDst(localPort, ip, port);
        return;
    }

    // Match target IPs - redirect to local proxy
    if (IsTargetIp(ip)) {
        StoreOrigDst(localPort, ip, port);
        remote->sin_addr.S_un.S_addr = htonl(0x0100007F);
        remote->sin_port = htons(21539);
        remote->sin_family = AF_INET;
    }
}

NTSTATUS NTAPI NotifyFn(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER* filter) {
    return STATUS_SUCCESS;
}

static BOOL CreateSharedMemory() {
    g_shmOrig = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, SHM_SIZE, SHM_ORIG_NAME);
    if (!g_shmOrig) return FALSE;
    g_origView = (BYTE*)MapViewOfFile(g_shmOrig, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
    if (!g_origView) return FALSE;
    ZeroMemory(g_origView, SHM_SIZE);

    g_shmTargets = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, 256, SHM_TARGET_NAME);
    if (!g_shmTargets) return FALSE;
    g_targetView = (BYTE*)MapViewOfFile(g_shmTargets, FILE_MAP_ALL_ACCESS, 0, 0, 256);
    if (!g_targetView) return FALSE;
    ZeroMemory(g_targetView, 256);
    return TRUE;
}

__declspec(dllexport) BOOL WINAPI Initialize() {
    if (!CreateSharedMemory()) return FALSE;

    FWPM_SESSION session;
    ZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    HANDLE engine = NULL;
    if (FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine)) {
        return FALSE;
    }
    g_engine = engine;

    // Register callout
    FWPM_CALLOUT callout;
    ZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = CALLOUT_GUID;
    callout.displayData.name = L"MRPORT Redirect";
    callout.displayData.description = L"Redirect matching connections to local proxy";
    callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

    NTSTATUS result = FwpmCalloutAdd(engine, &callout, NULL, NULL);
    // Ignore FWP_E_ALREADY_EXISTS

    // Add sublayer
    FWPM_SUBLAYER sublayer;
    ZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = SUBLAYER_GUID;
    sublayer.displayData.name = L"MRPORT";
    sublayer.displayData.description = L"MRPORT proxy sublayer";
    sublayer.weight = 0x100;
    FwpmSubLayerAdd(engine, &sublayer, NULL);

    return TRUE;
}

__declspec(dllexport) BOOL WINAPI AddTargetFilter(ULONG targetIp) {
    if (!g_engine) return FALSE;

    FWPM_FILTER filter;
    ZeroMemory(&filter, sizeof(filter));
    filter.subLayerKey = SUBLAYER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    filter.displayData.name = L"MRPORT rule";
    filter.displayData.description = L"";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = CALLOUT_GUID;
    filter.numFilterConditions = 2;

    FWPM_FILTER_CONDITION conds[2];
    ZeroMemory(conds, sizeof(conds));
    conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT32;
    conds[0].conditionValue.uint32 = targetIp;

    conds[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT8;
    conds[1].conditionValue.uint8 = IPPROTO_TCP;

    filter.filterCondition = conds;
    return FwpmFilterAdd(g_engine, &filter, NULL, NULL) == 0;
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
    if (g_engine) { FwpmEngineClose(g_engine); g_engine = NULL; }
    if (g_targetView) { UnmapViewOfFile(g_targetView); g_targetView = NULL; }
    if (g_shmTargets) { CloseHandle(g_shmTargets); g_shmTargets = NULL; }
    if (g_origView) { UnmapViewOfFile(g_origView); g_origView = NULL; }
    if (g_shmOrig) { CloseHandle(g_shmOrig); g_shmOrig = NULL; }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) { return TRUE; }
