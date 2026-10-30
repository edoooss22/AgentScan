using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AgentScan.Native;

internal sealed class SignatureResult
{
    public int Status = -1;
    public string Method = "не проверялась";
    public string? Signer;
    public string? CatalogPath;

    public bool Valid => Status == 0;

    public string Describe()
    {
        string s = Status switch
        {
            -1 => "не проверялась",
            0 => $"валидна ({Method})",
            unchecked((int)0x800B0100) => "НЕ ПОДПИСАН",
            unchecked((int)0x800B0101) => "сертификат просрочен",
            unchecked((int)0x800B0109) => "недоверенный корень",
            unchecked((int)0x800B010A) => "цепочка не построена",
            unchecked((int)0x80096010) => "ПОДПИСЬ НЕ СОВПАДАЕТ (файл изменён)",
            unchecked((int)0x80092003) => "ошибка чтения файла",
            unchecked((int)0x80070002) => "файл не найден",
            _ => $"0x{Status:X8}",
        };
        if (Signer is not null) s += $"; подписант: {Signer}";
        return s;
    }
}

internal static unsafe class Authenticode
{
    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll")]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin,
        IntPtr subsystem, string? hashAlgorithm, IntPtr policy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr hCatAdmin,
        IntPtr subsystem, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin,
        IntPtr hFile, ref uint pcbHash, byte* pbHash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile,
        ref uint pcbHash, byte* pbHash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin,
        byte* pbHash, uint cbHash, uint flags, IntPtr prevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin,
        IntPtr hCatInfo, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sa, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    public static SignatureResult Verify(string path)
    {
        var res = new SignatureResult();
        if (!File.Exists(path)) { res.Status = unchecked((int)0x80070002); return res; }

        int embedded = VerifyEmbedded(path);
        if (embedded == 0)
        {
            res.Status = 0;
            res.Method = "встроенная";
            res.Signer = TryGetSigner(path);
            return res;
        }

        var cat = VerifyCatalog(path);
        if (cat is not null)
        {
            res.Status = cat.Value.status;
            res.Method = "каталог";
            res.CatalogPath = cat.Value.catalog;
            if (cat.Value.status == 0 && cat.Value.catalog is not null)
                res.Signer = TryGetSigner(cat.Value.catalog);
            if (res.Status == 0) return res;
        }

        res.Status = embedded;
        res.Method = "встроенная";
        return res;
    }

    private static int VerifyEmbedded(string path)
    {
        IntPtr pPath = Marshal.StringToHGlobalUni(path);
        IntPtr pFi = Marshal.AllocHGlobal(sizeof(WINTRUST_FILE_INFO));
        try
        {
            var fi = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = pPath,
            };
            Marshal.StructureToPtr(fi, pFi, false);

            var wd = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = 2,
                fdwRevocationChecks = 0,
                dwUnionChoice = 1,
                pUnion = pFi,
                dwStateAction = 0,
                dwProvFlags = 0x00001000,
            };
            var action = GenericVerifyV2;
            return WinVerifyTrust((IntPtr)(-1), ref action, ref wd);
        }
        finally
        {
            Marshal.FreeHGlobal(pFi);
            Marshal.FreeHGlobal(pPath);
        }
    }

    private static (int status, string? catalog)? VerifyCatalog(string path)
    {
        IntPtr hFile = CreateFileW(path, 0x80000000 , 0x1 | 0x2 | 0x4,
            IntPtr.Zero, 3 , 0x80, IntPtr.Zero);
        if (hFile == (IntPtr)(-1)) return null;

        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        try
        {
            bool sha256 = CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero,
                "SHA256", IntPtr.Zero, 0);
            if (!sha256 && !CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
                return null;

            uint cbHash = 64;
            byte* hash = stackalloc byte[64];
            bool ok = sha256
                ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, hash, 0)
                : CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, hash, 0);
            if (!ok) return null;

            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return null;

            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return null;

            var tag = new StringBuilder((int)cbHash * 2);
            for (int i = 0; i < cbHash; i++) tag.Append(hash[i].ToString("X2"));

            IntPtr pCatalogFile = Marshal.StringToHGlobalUni(ci.wszCatalogFile);
            IntPtr pMemberTag = Marshal.StringToHGlobalUni(tag.ToString());
            IntPtr pMemberFile = Marshal.StringToHGlobalUni(path);
            IntPtr pHash = Marshal.AllocHGlobal((int)cbHash);
            IntPtr pCi = Marshal.AllocHGlobal(sizeof(WINTRUST_CATALOG_INFO));
            try
            {
                Buffer.MemoryCopy(hash, (void*)pHash, cbHash, cbHash);
                var wci = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                    pcwszCatalogFilePath = pCatalogFile,
                    pcwszMemberTag = pMemberTag,
                    pcwszMemberFilePath = pMemberFile,
                    hMemberFile = hFile,
                    pbCalculatedFileHash = pHash,
                    cbCalculatedFileHash = cbHash,
                    hCatAdmin = hCatAdmin,
                };
                Marshal.StructureToPtr(wci, pCi, false);

                var wd = new WINTRUST_DATA
                {
                    cbStruct = (uint)sizeof(WINTRUST_DATA),
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 2,
                    pUnion = pCi,
                    dwStateAction = 0,
                    dwProvFlags = 0x00001000,
                };
                var action = GenericVerifyV2;
                int st = WinVerifyTrust((IntPtr)(-1), ref action, ref wd);
                return (st, ci.wszCatalogFile);
            }
            finally
            {
                Marshal.FreeHGlobal(pCi);
                Marshal.FreeHGlobal(pHash);
                Marshal.FreeHGlobal(pMemberFile);
                Marshal.FreeHGlobal(pMemberTag);
                Marshal.FreeHGlobal(pCatalogFile);
            }
        }
        catch { return null; }
        finally
        {
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
            CloseHandle(hFile);
        }
    }

    private static string? TryGetSigner(string path)
    {
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch { return null; }
    }
}
