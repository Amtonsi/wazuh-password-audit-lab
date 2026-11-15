// Получаем только метаданные локального SAM. Изменение учётных записей не выполняем.
// C# 3 / .NET 3.5: используем совместно с Windows PowerShell 2.0 и более поздними.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SiemPasswordAuditV2 {
    public sealed class UserRecord {
        public string Name, Sid, ReadError = "";
        public uint AgeSeconds, Flags;
        public bool DetailKnown, ExpiredReported, InternetIdentity, InternetIdentityKnown;
    }
    public sealed class Snapshot {
        public List<UserRecord> Users = new List<UserRecord>();
        public bool EnumerationComplete, IdentityComplete, PolicyKnown, MaxAgeUnlimited;
        public uint MaxAgeSeconds, MinAgeSeconds, MinLength, HistoryLength;
        public string EnumerationError = "", PolicyError = "";
    }
    public static class Reader {
        [StructLayout(LayoutKind.Sequential)] private struct USER_INFO_0 { public IntPtr name; }
        [StructLayout(LayoutKind.Sequential)] private struct USER_INFO_4 {
            public IntPtr name, password;
            public uint password_age, priv;
            public IntPtr home_dir, comment;
            public uint flags;
            public IntPtr script_path;
            public uint auth_flags;
            public IntPtr full_name, usr_comment, parms, workstations;
            public uint last_logon, last_logoff, acct_expires, max_storage, units_per_week;
            public IntPtr logon_hours;
            public uint bad_pw_count, num_logons;
            public IntPtr logon_server;
            public uint country_code, code_page;
            public IntPtr user_sid;
            public uint primary_group_id;
            public IntPtr profile, home_dir_drive;
            public uint password_expired;
        }
        [StructLayout(LayoutKind.Sequential)] private struct USER_INFO_24 {
            [MarshalAs(UnmanagedType.Bool)] public bool internet_identity;
            public uint flags;
            public IntPtr internet_provider_name, internet_principal_name, user_sid;
        }
        [StructLayout(LayoutKind.Sequential)] private struct USER_MODALS_INFO_0 {
            public uint min_passwd_len, max_passwd_age, min_passwd_age, force_logoff, password_hist_len;
        }
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
        private static extern int NetUserEnum(string server, int level, int filter, out IntPtr buffer,
            int preferredLength, out int read, out int total, ref int resume);
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
        private static extern int NetUserGetInfo(string server, string user, int level, out IntPtr buffer);
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
        private static extern int NetUserModalsGet(string server, int level, out IntPtr buffer);
        [DllImport("Netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);

        private static string Error(int code) {
            return "Win32 " + code + ": " + new Win32Exception(code).Message;
        }
        private static UserRecord ReadUser(string name) {
            UserRecord row = new UserRecord(); row.Name = name;
            IntPtr buffer = IntPtr.Zero;
            try {
                int rc = NetUserGetInfo(null, name, 4, out buffer);
                if (rc != 0) { row.ReadError = Error(rc); return row; }
                USER_INFO_4 u = (USER_INFO_4)Marshal.PtrToStructure(buffer, typeof(USER_INFO_4));
                // Поле password не читаем: API возвращает NULL, а содержимое пароля нам не требуется.
                if (u.user_sid != IntPtr.Zero) row.Sid = new SecurityIdentifier(u.user_sid).Value;
                row.AgeSeconds = u.password_age; row.Flags = u.flags;
                row.ExpiredReported = u.password_expired != 0;
                row.DetailKnown = true;
            } catch (Exception e) { row.ReadError = e.Message; }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }

            // Уровень 24 существует начиная с Windows 8. Не выдаём SAM-возраст за возраст облачного пароля.
            buffer = IntPtr.Zero;
            try {
                int rc = NetUserGetInfo(null, name, 24, out buffer);
                if (rc == 0) {
                    USER_INFO_24 u = (USER_INFO_24)Marshal.PtrToStructure(buffer, typeof(USER_INFO_24));
                    row.InternetIdentity = u.internet_identity; row.InternetIdentityKnown = true;
                } else if (rc == 124 && Environment.OSVersion.Version.CompareTo(new Version(6, 2)) < 0) {
                    row.InternetIdentityKnown = true; // На Windows 7 отсутствуют интернет-связанные SAM-входы.
                } else row.ReadError += " Identity: " + Error(rc);
            } catch (Exception e) { row.ReadError += " Identity: " + e.Message; }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            return row;
        }
        public static Snapshot Read() {
            Snapshot result = new Snapshot();
            IntPtr policy = IntPtr.Zero;
            try {
                int rc = NetUserModalsGet(null, 0, out policy);
                if (rc == 0) {
                    USER_MODALS_INFO_0 p = (USER_MODALS_INFO_0)Marshal.PtrToStructure(policy, typeof(USER_MODALS_INFO_0));
                    if (p.max_passwd_age != UInt32.MaxValue && p.max_passwd_age < 86400)
                        result.PolicyError = "Invalid maximum password age: " + p.max_passwd_age;
                    else {
                        result.PolicyKnown = true; result.MaxAgeUnlimited = p.max_passwd_age == UInt32.MaxValue;
                        result.MaxAgeSeconds = p.max_passwd_age; result.MinAgeSeconds = p.min_passwd_age;
                        result.MinLength = p.min_passwd_len; result.HistoryLength = p.password_hist_len;
                    }
                } else result.PolicyError = Error(rc);
            } catch (Exception e) { result.PolicyError = e.Message; }
            finally { if (policy != IntPtr.Zero) NetApiBufferFree(policy); }

            int resume = 0;
            Dictionary<string,bool> names = new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);
            try {
                while (true) {
                    IntPtr buffer = IntPtr.Zero; int count, total; int previousResume = resume;
                    try {
                        // FILTER_NORMAL_ACCOUNT=2; server=NULL означает только данный компьютер.
                        int rc = NetUserEnum(null, 0, 2, out buffer, 65536, out count, out total, ref resume);
                        if (rc != 0 && rc != 234) { result.EnumerationError = Error(rc); break; }
                        int size = Marshal.SizeOf(typeof(USER_INFO_0));
                        for (int i=0; i<count; i++) {
                            USER_INFO_0 u = (USER_INFO_0)Marshal.PtrToStructure(
                                new IntPtr(buffer.ToInt64() + i * size), typeof(USER_INFO_0));
                            string name = Marshal.PtrToStringUni(u.name);
                            if (String.IsNullOrEmpty(name) || names.ContainsKey(name))
                                throw new InvalidOperationException("Empty or duplicate enumerated account");
                            names.Add(name, true);
                            result.Users.Add(ReadUser(name));
                        }
                        if (rc == 0) { result.EnumerationComplete = true; break; }
                        if (count == 0 && resume == previousResume)
                            throw new InvalidOperationException("Enumeration did not advance");
                    } finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
                }
            } catch (Exception e) { result.EnumerationError = e.Message; }
            Dictionary<string,bool> sids = new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);
            result.IdentityComplete = result.EnumerationComplete;
            foreach (UserRecord row in result.Users) {
                if (String.IsNullOrEmpty(row.Sid) || sids.ContainsKey(row.Sid)) result.IdentityComplete = false;
                else sids.Add(row.Sid, true);
            }
            return result;
        }
    }
}
