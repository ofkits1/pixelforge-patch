#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/ENTRY:DllMain")
#pragma comment(linker, "/export:GetFileVersionInfoA=version_orig.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=version_orig.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=version_orig.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=version_orig.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_orig.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=version_orig.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=version_orig.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version_orig.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_orig.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=version_orig.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=version_orig.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=version_orig.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=version_orig.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=version_orig.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=version_orig.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=version_orig.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=version_orig.VerQueryValueW")
#pragma function(memcpy, memset, memcmp)

#define HM_PIXELFORGE 0x2ED7AFEFu

/* _check_trial RESUME + LOAD_GLOBAL TRIAL_DAYS + LOAD_SMALL_INT 0 + COMPARE <= */
static const unsigned char kNeedle[] = {
    0x80, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5E, 0x00, 0x38, 0x3A
};
/* overwrite after RESUME: LOAD_CONST (False,0); RETURN_VALUE */
static const unsigned char kStub[] = { 0x52, 0x01, 0x23, 0x00 };

static HMODULE g_orig;
static volatile LONG g_done;

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    while (n--) {
        if (*p != *q)
            return (int)*p - (int)*q;
        p++;
        q++;
    }
    return 0;
}

static unsigned hmix(unsigned h, unsigned char b)
{
    h ^= (unsigned)b;
    h = ((h << 7) | (h >> 25)) + 0x6D2B79F5u;
    h ^= h >> 11;
    return h;
}

static unsigned h_wfnv(const wchar_t *s, unsigned nbytes)
{
    unsigned h = 0xA5A5C3E1u;
    unsigned n, i;
    if (!s || nbytes < 2)
        return 0;
    n = nbytes / 2u;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)(s[i] & 0xFF);
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c + 32);
        h = hmix(h, c);
    }
    return h;
}

typedef struct _USTR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} USTR;

typedef struct _LDR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    USTR FullDllName;
    USTR BaseDllName;
} LDR;

typedef struct _PEB_LDR {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR;

typedef struct _PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR *Ldr;
} PEB;

static unsigned host_exe_hash(void)
{
    PEB *peb = (PEB *)__readgsqword(0x60);
    LIST_ENTRY *head, *cur;
    LDR *e;
    if (!peb || !peb->Ldr)
        return 0;
    head = &peb->Ldr->InLoadOrderModuleList;
    cur = head->Flink;
    if (!cur || cur == head)
        return 0;
    e = (LDR *)cur;
    if (!e->BaseDllName.Buffer || e->BaseDllName.Length < 4)
        return 0;
    return h_wfnv(e->BaseDllName.Buffer, e->BaseDllName.Length);
}

static int patch_at(BYTE *p)
{
    DWORD old_prot, tmp;
    if (memcmp(p + 2, kStub, sizeof(kStub)) == 0)
        return 1;
    if (!VirtualProtect(p, 8, PAGE_EXECUTE_READWRITE, &old_prot))
        return 0;
    memcpy(p + 2, kStub, sizeof(kStub));
    VirtualProtect(p, 8, old_prot, &tmp);
    FlushInstructionCache(GetCurrentProcess(), p, 8);
    return 1;
}

static void apply_unlock(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr;
    SIZE_T n;
    unsigned i;

    if (g_done)
        return;
    if (host_exe_hash() != HM_PIXELFORGE)
        return;
    addr = 0;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xEE) &&
            !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize >= sizeof(kNeedle)) {
            BYTE *b = (BYTE *)mbi.BaseAddress;
            SIZE_T lim = mbi.RegionSize - sizeof(kNeedle);
            for (n = 0; n < lim; ++n) {
                int ok = 1;
                for (i = 0; i < sizeof(kNeedle); ++i) {
                    if (b[n + i] != kNeedle[i]) {
                        ok = 0;
                        break;
                    }
                }
                if (ok && patch_at(b + n)) {
                    InterlockedExchange(&g_done, 1);
                    return;
                }
            }
        }
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if (!addr)
            break;
    }
}

static DWORD WINAPI apply_later(LPVOID p)
{
    unsigned n = 0;
    (void)p;
    for (;;) {
        apply_unlock();
        if (g_done || ++n >= 400u)
            break;
        Sleep(25u);
    }
    return 0;
}

static wchar_t *find_last_slash(wchar_t *s)
{
    wchar_t *last = NULL;
    while (s && *s) {
        if (*s == L'\\')
            last = s;
        s++;
    }
    return last;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    wchar_t path[MAX_PATH];
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        if (GetModuleFileNameW(h, path, MAX_PATH)) {
            lstrcpyW(find_last_slash(path) + 1, L"version_orig.dll");
            g_orig = LoadLibraryW(path);
        }
        apply_unlock();
        if (!g_done)
            QueueUserWorkItem(apply_later, 0, WT_EXECUTELONGFUNCTION);
    } else if (reason == DLL_PROCESS_DETACH && g_orig) {
        FreeLibrary(g_orig);
        g_orig = NULL;
    }
    return TRUE;
}
