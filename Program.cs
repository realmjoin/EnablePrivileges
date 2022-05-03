using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

class Program
{
    static int Main(string[] args)
    {
        var names = args.Where(x => x.StartsWith("Se")).ToList();

        if (names.Count == 0)
        {
            Console.WriteLine("No privileges specified! Valid privileges begin with 'Se'.");
            return 1;
        }

        var privileges = new LuidAndAttributes[names.Count];

        // Lookup the Luid of each privilege
        for (var i = 0; i < names.Count; i++)
        {
            Console.WriteLine($"Enable privilege: {names[i]}");

            privileges[i].Attributes = 0x02; // SE_PRIVILEGE_ENABLED

            if (!LookupPrivilegeValue(null, names[i], ref privileges[i].Luid))
            {
                throw new Win32Exception();
            }
        }

        var parent = ParentProcessUtilities.GetParentProcess();

        if (parent is null)
        {
            Console.Error.WriteLine("Could not find parent process!");
            return 100;
        }

        using var processHandle = OpenProcess(ProcessAccessFlags.QueryInformation, false, parent.Id);

        if (processHandle.IsInvalid)
            throw new Win32Exception();

        if (!OpenProcessToken(processHandle.DangerousGetHandle(), TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges, out var processToken))
            throw new Win32Exception();

        using (processToken)
        {
            var handle = GetPinnedTokenPrivileges(privileges);

            try
            {
                if (!AdjustTokenPrivileges(processToken, false, handle.AddrOfPinnedObject(), 0, IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }
            finally
            {
                if (handle.IsAllocated) handle.Free();
            }
        }

        return 0;
    }

    static GCHandle GetPinnedTokenPrivileges(LuidAndAttributes[] privileges)
    {
        var newState = new TokenPrivileges
        {
            PrivilegeCount = (uint)privileges.Length,
            Privileges = new LuidAndAttributes[1]
        };

        var bufferSize = Marshal.SizeOf<TokenPrivileges>() + Marshal.SizeOf<LuidAndAttributes>() * (int)(newState.PrivilegeCount - 1);
        var buffer = new byte[bufferSize];
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

        var ptr = handle.AddrOfPinnedObject();

        Marshal.StructureToPtr(newState, ptr, false);

        for (var i = 0; i < privileges.Length; i++)
            Marshal.StructureToPtr(privileges[i], ptr + Marshal.SizeOf(newState.PrivilegeCount) + (Marshal.SizeOf<LuidAndAttributes>() * i), false);

        return handle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct Luid
    {
        public uint LowPart;
        public uint HighPart;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TokenPrivileges
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LuidAndAttributes[] Privileges;
    }

    [Flags]
    enum ProcessAccessFlags
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern SafeProcessHandle OpenProcess(
        ProcessAccessFlags access,
        bool inherit,
        int processId);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern
    bool OpenProcessToken(
        [In] IntPtr ProcessHandle,
        [In] TokenAccessLevels DesiredAccess,
        [Out] out SafeAccessTokenHandle TokenHandle);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "LookupPrivilegeValueW",
        CharSet = CharSet.Auto,
        SetLastError = true,
        ExactSpelling = true,
        BestFitMapping = false)]
    static extern
    bool LookupPrivilegeValue(
        [In] string? lpSystemName,
        [In] string? lpName,
        [In, Out] ref Luid Luid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern
    bool AdjustTokenPrivileges(
        [In] SafeAccessTokenHandle TokenHandle,
        [In] bool DisableAllPrivileges,
        [In] IntPtr NewState,
        [In] uint BufferLength,
        [In] IntPtr Null1,
        [In] IntPtr Null2);
}