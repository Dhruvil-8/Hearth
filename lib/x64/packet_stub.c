#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}

__declspec(dllexport) void* PacketOpenAdapter(char* AdapterName) { return NULL; }
__declspec(dllexport) void PacketCloseAdapter(void* lpAdapter) {}
__declspec(dllexport) void* PacketAllocatePacket(void) { return NULL; }
__declspec(dllexport) void PacketInitPacket(void* lpPacket, void* Buffer, DWORD Length) {}
__declspec(dllexport) void PacketFreePacket(void* lpPacket) {}
__declspec(dllexport) BOOLEAN PacketReceivePacket(void* AdapterObject, void* lpPacket, BOOLEAN Sync) { return FALSE; }
__declspec(dllexport) BOOLEAN PacketSendPacket(void* AdapterObject, void* lpPacket, BOOLEAN Sync) { return FALSE; }
__declspec(dllexport) BOOLEAN PacketSetHwFilter(void* AdapterObject, ULONG Filter) { return FALSE; }
__declspec(dllexport) BOOLEAN PacketGetAdapterNames(char* pStr, ULONG* BufferSize) { return FALSE; }
__declspec(dllexport) BOOLEAN PacketSetMinToCopy(void* AdapterObject, int nbytes) { return FALSE; }
__declspec(dllexport) BOOLEAN PacketSetBuff(void* AdapterObject, int dim) { return FALSE; }
__declspec(dllexport) BOOLEAN PacketSetReadTimeout(void* AdapterObject, int timeout) { return FALSE; }
