using BepInEx.Logging;
using Mono.Cecil;
using System.Runtime.InteropServices;

namespace HideOnlineFix;

public unsafe static class Preload
{
    public static IEnumerable<string> TargetDLLs { get; } = [];

    private const string TargetDllName = "OnlineFix64.dll";

    private static readonly ManualLogSource Logger = BepInEx.Logging.Logger.CreateLogSource("HideOnlineFix");

    public static void Initialize()
    {
        Logger.LogInfo($"Attempting to hide {TargetDllName}...");
        try
        {
            HideModule();
        }
        catch (Exception e)
        {
            Logger.LogError($"Failed to hide module: {e}");
        }
        Logger.LogInfo("Bye");
    }

    private static void HideModule()
    {
        IntPtr pebAddress = GetPebAddress();
        if (pebAddress == IntPtr.Zero)
        {
            Logger.LogError("Could not locate PEB.");
            return;
        }

        byte* peb = (byte*)pebAddress;
        PEB_LDR_DATA* ldr = *(PEB_LDR_DATA**)(peb + 0x18);
        LIST_ENTRY* head = (LIST_ENTRY*)((byte*)ldr + 0x10);
        head = &ldr->InLoadOrderModuleList;

        LIST_ENTRY* current = head->Flink;
        bool found = false;

        while (current != head)
        {
            LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)current;

            string currentName = entry->FullDllName.ToString();

            if (currentName != null && currentName.EndsWith(TargetDllName, StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogInfo($"Found {TargetDllName} at 0x{(ulong)entry:X}. Unlinking...");

                UnlinkEntry(&entry->InLoadOrderLinks);
                if (entry->HashLinks.Flink != null && entry->HashLinks.Blink != null)
                {
                    UnlinkEntry(&entry->HashLinks);
                }
                else
                {
                    Logger.LogError("HashLinks pointers are null?!");
                }

                found = true;
                break;
            }

            current = current->Flink;
        }

        if (!found)
        {
            Logger.LogInfo($"Module {TargetDllName} was not found in the list; no need to hide anything.");
        }
    }

    private static void UnlinkEntry(LIST_ENTRY* entry)
    {
        LIST_ENTRY* blink = entry->Blink;
        LIST_ENTRY* flink = entry->Flink;
        blink->Flink = flink;
        flink->Blink = blink;
        entry->Flink = null;
        entry->Blink = null;
    }


    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength);

    private static IntPtr GetPebAddress()
    {
        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
        int status = NtQueryInformationProcess(
            System.Diagnostics.Process.GetCurrentProcess().Handle,
            0,
            ref pbi,
            Marshal.SizeOf(pbi),
            out _
        );

        return status == 0 ? pbi.PebBaseAddress : IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_1;
        public IntPtr Reserved2_2;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY
    {
        public LIST_ENTRY* Flink;
        public LIST_ENTRY* Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public char* Buffer;

        public override string ToString()
        {
            if (Buffer == null || Length == 0) return null;
            return new string(Buffer, 0, Length / 2);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PEB_LDR_DATA
    {
        public uint Length;
        public byte Initialized;
        private fixed byte padding[3];
        public IntPtr SsHandle;
        public LIST_ENTRY InLoadOrderModuleList;
        public LIST_ENTRY InMemoryOrderModuleList;
        public LIST_ENTRY InInitializationOrderModuleList;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct LDR_DATA_TABLE_ENTRY
    {
        [FieldOffset(0x00)] public LIST_ENTRY InLoadOrderLinks;
        [FieldOffset(0x10)] public LIST_ENTRY InMemoryOrderLinks;
        [FieldOffset(0x20)] public LIST_ENTRY InInitializationOrderLinks;
        [FieldOffset(0x30)] public IntPtr DllBase;
        [FieldOffset(0x38)] public IntPtr EntryPoint;
        [FieldOffset(0x40)] public uint SizeOfImage;
        [FieldOffset(0x48)] public UNICODE_STRING FullDllName;
        [FieldOffset(0x58)] public UNICODE_STRING BaseDllName;
        [FieldOffset(0x68)] public uint Flags;
        [FieldOffset(0x6C)] public ushort ObsoleteLoadCount;
        [FieldOffset(0x6E)] public ushort TlsIndex;
        [FieldOffset(0x70)] public LIST_ENTRY HashLinks;
        [FieldOffset(0x80)] public uint TimeDateStamp;
    }

    public static void Patch(AssemblyDefinition assembly)
    {
    }
}
