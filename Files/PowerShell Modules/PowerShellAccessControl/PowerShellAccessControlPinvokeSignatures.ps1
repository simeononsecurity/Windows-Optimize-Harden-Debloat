
Add-Type @"
using System;
using System.Runtime.InteropServices;

namespace PowerShellAccessControl {
    namespace PInvoke {
        // There are more than defined here. See http://msdn.microsoft.com/en-us/library/cc230369.aspx
        [Flags]
        public enum SecurityInformation : uint {
            Owner           = 0x00000001,
            Group           = 0x00000002,
            Dacl            = 0x00000004,
            Sacl            = 0x00000008,
            All             = 0x0000000f,
            Label           = 0x00000010,
            Attribute       = 0x00000020,
            Scope           = 0x00000040,
            ProtectedDacl   = 0x80000000,
            ProtectedSacl   = 0x40000000,
            UnprotectedDacl = 0x20000000,
            UnprotectedSacl = 0x10000000
        }

        public struct InheritArray {
            public Int32 GenerationGap;
            [MarshalAs(UnmanagedType.LPTStr)] public string AncestorName;
        }

        public struct GenericMapping {
            public Int32 GenericRead;
            public Int32 GenericWrite;
            public Int32 GenericExecute;
            public Int32 GenericAll;
        }

        public class advapi32 {

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446645%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
            public static extern uint GetNamedSecurityInfo(
                string ObjectName,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446654%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", SetLastError=true)]
            public static extern uint GetSecurityInfo(
                IntPtr handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446650%28v=vs.85%29.aspx
            [DllImport("advapi32.dll")]
            public static extern Int32 GetSecurityDescriptorLength(
                IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379579%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
            public static extern uint SetNamedSecurityInfo(
                string ObjectName,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379588(v=vs.85).aspx
            [DllImport("advapi32.dll")]
            public static extern Int32 SetSecurityInfo(
                IntPtr handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );

            [DllImport("advapi32.dll", EntryPoint = "GetInheritanceSourceW", CharSet = CharSet.Unicode)]
            public static extern UInt32 GetInheritanceSource(
                    [MarshalAs(UnmanagedType.LPTStr)] string ObjectName,
                    System.Security.AccessControl.ResourceType ObjectType,
                    SecurityInformation SecurityInfo,
                    [MarshalAs(UnmanagedType.Bool)]bool Container,
                    IntPtr ObjectClassGuids,
                    UInt32 GuidCount,
                    byte[] Acl,
                    IntPtr pfnArray,
                    ref GenericMapping GenericMapping,
                    IntPtr InheritArray                
            );

            [DllImport("advapi32.dll", EntryPoint = "GetInheritanceSourceW", CharSet = CharSet.Unicode)]
            public static extern UInt32 GetInheritanceSource(
                    [MarshalAs(UnmanagedType.LPTStr)] string ObjectName,
                    System.Security.AccessControl.ResourceType ObjectType,
                    SecurityInformation SecurityInfo,
                    [MarshalAs(UnmanagedType.Bool)]bool Container,
                    ref Guid[] ObjectClassGuids,   // double pointer
                    UInt32 GuidCount,
                    byte[] Acl,
                    IntPtr pfnArray,
                    ref GenericMapping GenericMapping,
                    IntPtr InheritArray                
            );

            [DllImport("advapi32.dll")]
            public static extern UInt32 FreeInheritedFromArray(
                IntPtr InheritArray,
                UInt16 AceCnt,
                IntPtr pfnArray
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa375202(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="AdjustTokenPrivileges", SetLastError=true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AdjustTokenPrivileges(
                IntPtr TokenHandle, 
                [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges, 
                ref TOKEN_PRIVILEGES NewState, 
                UInt32 BufferLengthInBytes,
                ref TOKEN_PRIVILEGES PreviousState, 
                out UInt32 ReturnLengthInBytes
            );

            public static Int32 AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes) {
                if (__AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, ref NewState, BufferLengthInBytes, ref PreviousState, out ReturnLengthInBytes)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379180(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupPrivilegeValue", SetLastError=true, CharSet=CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __LookupPrivilegeValue(
                string lpSystemName, 
                string lpName,
                out LUID lpLuid
            );

            public static Int32 LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid) {
                if (__LookupPrivilegeValue(lpSystemName, lpName, out lpLuid)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("advapi32.dll", EntryPoint="OpenProcessToken", SetLastError=true, CharSet=CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __OpenProcessToken(
                IntPtr ProcessHandle,
                System.Security.Principal.TokenAccessLevels DesiredAccess,
                out IntPtr TokenHandle
            );

            public static Int32 OpenProcessToken(IntPtr ProcessHandle, System.Security.Principal.TokenAccessLevels DesiredAccess, out IntPtr TokenHandle) {
                // Call original function:
                if (__OpenProcessToken(ProcessHandle, DesiredAccess, out TokenHandle)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [Flags]
            public enum PrivilegeAttributes : uint {
                Disabled         = 0x00000000,
                EnabledByDefault = 0x00000001,
                Enabled          = 0x00000002,
                Removed          = 0x00000004,
                UsedForAccess    = 0x80000000
            }

            public struct TOKEN_PRIVILEGES {
                public UInt32 PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst=1)]
                public LUID_AND_ATTRIBUTES [] Privileges;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct LUID_AND_ATTRIBUTES {
                public LUID Luid;
                public PrivilegeAttributes Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID {
                public UInt32 LowPart;
                public Int32 HighPart;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379159(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupAccountName", SetLastError=true)]
            static extern bool __LookupAccountName(
                string lpSystemName,
                string lpAccountName,
                [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
                ref UInt32 cbSid,
                System.Text.StringBuilder lpReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out SID_NAME_USE peUse
            );
            public static Int32 LookupAccountName(string lpSystemName, string lpAccountName, byte[] Sid, ref UInt32 cbSid, System.Text.StringBuilder lpReferencedDomainName, ref UInt32 cchReferencedDomainName, out SID_NAME_USE peUse) {
                if (__LookupAccountName(lpSystemName, lpAccountName, Sid, ref cbSid, lpReferencedDomainName, ref cchReferencedDomainName, out peUse)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379166(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupAccountSid", SetLastError=true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __LookupAccountSid(
                string lpSystemName,
                [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
                System.Text.StringBuilder lpName,
                ref UInt32 cchName,
                System.Text.StringBuilder lpReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out SID_NAME_USE peUse
            );  

            public static Int32 LookupAccountSid(string lpSystemName, byte[] Sid, System.Text.StringBuilder lpName, ref UInt32 cchName, System.Text.StringBuilder lpReferencedDomainName, ref UInt32 cchReferencedDomainName, out SID_NAME_USE peUse) {
                if (__LookupAccountSid(lpSystemName, Sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out peUse)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379601(v=vs.85).aspx
            public enum SID_NAME_USE {
                User            = 1,
                Group,
                Domain,
                Alias,
                WellKnownGroup,
                DeletedAccount,
                Invalid,
                Unknown,
                Computer,
                Label
            }
        }

        public class kernel32 {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366745%28v=vs.85%29.aspx
            [DllImport("kernel32.dll")]
            public static extern uint LocalSize(
                IntPtr hMem
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366728%28v=vs.85%29.aspx
            [DllImport("kernel32.dll")]
            public static extern uint LocalFlags(
                IntPtr hMem
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366730%28v=vs.85%29.aspx
// SetLastError is true, but I'm not checking it yet...
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern IntPtr LocalFree(
                IntPtr hMem
            );

            [DllImport("kernel32.dll", EntryPoint="CloseHandle", SetLastError=true, CharSet=CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __CloseHandle(
                IntPtr hObject
            );

            public static Int32 CloseHandle(IntPtr hObject) {
                if (__CloseHandle(hObject)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("kernel32.dll", EntryPoint="GetFileAttributesW", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern UInt32 GetFileAttributes(
                string lpFileName
            );

        }

        namespace AuthZEnums {
            [Flags]
            public enum AuthzResourceManagerFlags : int {
                None = 0,
                NoAudit = 0x1,
                InitializeUnderImpersonation = 0x2,
                ValidInitFlags = (NoAudit | InitializeUnderImpersonation)
            };

            [Flags]
            public enum AuthzContextFlags : int {
                None = 0,
                SkipTokenGroups = 0x2,
                RequireS4ULogon = 0x4,
                ComputePrivileges = 0x8
            };

            [Flags]
            public enum AuthzAccessCheckFlags : int {
                None = 0,
                NoDeepCopySD = 0x00000001
            };

            [Flags]
            public enum AuthzInitializeResourceManagerExFlags : int {
                None = 0,
                NoAudit = 0x1,
                InitializeUnderImpersonation = 0x2,
                NoCentralAccessPolicies = 0x4
            };

            [Flags]
            public enum AuthzGenerateFlags : int {
                None = 0,
                SuccessAudit = 0x00000001,
                FailureAudit = 0x00000002
            };

            public enum AuthzContextInformationClass : int {
                UserSid = 1,
                GroupsSids,
                RestrictedSids,
                Privileges,
                ExpirationTime,
                ServerContext,
                Identifier,
                Source,
                All,
                AuthenticationId,
                SecurityAttributes,
                DeviceSids,
                UserClaims,
                DeviceClaims,
                AppContainerSid,
                CapabilitySids
            };
 
            public enum AuthzSecurityAttributeOperation : int {
                None = 0,
                ReplaceAll,
                Add,
                Delete,
                Replace
            };

            public enum AuthzSecurityAttributeValueType : ushort {
                Invalid = 0x0,
                Int     = 0x1,
                String  = 0x3,
                Boolean = 0x6,
            };
 
            [Flags]
            public enum AuthzSecurityAttributeFlags : uint {
                None = 0x0,
                NonInheritable = 0x1,
                ValueCaseSensitive = 0x2,
            };

        }

        public class authz {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376322(v=vs.85).aspx
            public struct AUTHZ_ACCESS_REQUEST {
                public UInt32 DesiredAccess;
                public byte[] PrincipalSelfSid;
//                public OBJECT_TYPE_LIST[] ObjectTypeList;
                public IntPtr ObjectTypeList;
                public UInt32 ObjectTypeListLength;
                public IntPtr OptionalArguments;
            };

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379294(v=vs.85).aspx
            public struct OBJECT_TYPE_LIST {
                public UInt16 Level;
                public UInt16 Sbz;
                public IntPtr ObjectType;
//                public byte[] ObjectType;
            };

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376321(v=vs.85).aspx
            public struct AUTHZ_ACCESS_REPLY {
                public UInt32 ResultListLength;
                public IntPtr GrantedAccessMask;
                public IntPtr SaclEvaluationResults;
                public IntPtr Error;
            };

            public struct LUID {
                public UInt32 LowPart;
                public Int32 HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct AUTHZ_SECURITY_ATTRIBUTES_INFORMATION {
                public UInt16 Version;
                public UInt16 Reserved;
                public UInt32 AttributeCount;
                public IntPtr pAttributeV1;
            }
 
            [StructLayout(LayoutKind.Sequential)]
            public struct AUTHZ_SECURITY_ATTRIBUTE_V1 {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string Name;
                public UInt16 ValueType;
                public UInt32 Flags;
                public UInt32 ValueCount;
                public IntPtr Values;
            }

            [StructLayout(LayoutKind.Sequential)]
            public  struct AUTHZ_INIT_INFO_CLIENT {
                public UInt16 version;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string szResourceManagerName;
                public IntPtr pfnDynamicAccessCheck;
                public IntPtr pfnComputeDynamicGroups;
                public IntPtr pfnFreeDynamicGroups;
                public IntPtr pfnGetCentralAccessPolicy;
                public IntPtr pfnFreeCentralAccessPolicy;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/hh448464(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public  struct AUTHZ_RPC_INIT_INFO_CLIENT {
                public UInt16 version;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string ObjectUuid;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string ProtSeq;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string NetworkAddr;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string Endpoint;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string Options;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string ServerSpn;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa375788(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint="AuthzAccessCheck", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzAccessCheck(
                UInt32 flags, 
                IntPtr hAuthzClientContext,
                ref AUTHZ_ACCESS_REQUEST pRequest, 
                IntPtr AuditEvent,
                byte[] pSecurityDescriptor, 
                byte[] OptionalSecurityDescriptorArray,
                UInt32 OptionalSecurityDescriptorCount, 
                ref AUTHZ_ACCESS_REPLY pReply, 
                out IntPtr phAccessCheckResults
            );

            public static Int32 AuthzAccessCheck(
                UInt32 flags, 
                IntPtr hAuthzClientContext,
                ref AUTHZ_ACCESS_REQUEST pRequest, 
                IntPtr AuditEvent,
                byte[] pSecurityDescriptor, 
                byte[] OptionalSecurityDescriptorArray,
                UInt32 OptionalSecurityDescriptorCount, 
                ref AUTHZ_ACCESS_REPLY pReply, 
                out IntPtr phAccessCheckResults
            ) {
                if (__AuthzAccessCheck(flags, hAuthzClientContext, ref pRequest, AuditEvent, pSecurityDescriptor, OptionalSecurityDescriptorArray, OptionalSecurityDescriptorCount, ref pReply, out phAccessCheckResults)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376309(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzInitializeContextFromSid", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeContextFromSid(
                UInt32 flags, 
                byte[] UserSid, 
                IntPtr hAuthzResourceManager, 
                IntPtr pExpirationTime,
                LUID Identifier, 
                IntPtr DynamicGroupArgs, 
                out IntPtr pAuthzClientContext
            );

            public static Int32 AuthzInitializeContextFromSid(
                UInt32 flags, 
                byte[] UserSid, 
                IntPtr hAuthzResourceManager, 
                IntPtr pExpirationTime,
                LUID Identifier, 
                IntPtr DynamicGroupArgs, 
                out IntPtr pAuthzClientContext
            ) {
                if (__AuthzInitializeContextFromSid(flags, UserSid, hAuthzResourceManager, pExpirationTime, Identifier, DynamicGroupArgs, out pAuthzClientContext)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa375821(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzFreeContext", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzFreeContext(
                IntPtr hAuthzClientContext
            );

            public static Int32 AuthzFreeContext(
                IntPtr hAuthzClientContext
            ) {
                if (__AuthzFreeContext(hAuthzClientContext)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376313(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzInitializeResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeResourceManager(
                UInt32 flags, 
                IntPtr pfnAccessCheck, 
                IntPtr pfnComputeDynamicGroups,
                IntPtr pfnFreeDynamicGroups, 
                string szResourceManagerName, 
                out IntPtr phAuthzResourceManager
            );

            public static Int32 AuthzInitializeResourceManager(
                UInt32 flags, 
                IntPtr pfnAccessCheck, 
                IntPtr pfnComputeDynamicGroups,
                IntPtr pfnFreeDynamicGroups, 
                string szResourceManagerName, 
                out IntPtr phAuthzResourceManager
            ) {
                if (__AuthzInitializeResourceManager(flags, pfnAccessCheck, pfnComputeDynamicGroups, pfnFreeDynamicGroups, szResourceManagerName, out phAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("authz.dll", EntryPoint = "AuthzInitializeResourceManagerEx", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeResourceManagerEx(
                Int32 Flags,
                ref AUTHZ_INIT_INFO_CLIENT pAuthzInitInfo,
                out IntPtr phAuthzResourceManager
            );

            public static Int32 AuthzInitializeResourceManagerEx(
                Int32 Flags,
                ref AUTHZ_INIT_INFO_CLIENT pAuthzInitInfo,
                out IntPtr phAuthzResourceManager
            ) {
                if (__AuthzInitializeResourceManagerEx(Flags, ref pAuthzInitInfo, out phAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("authz.dll", EntryPoint = "AuthzInitializeRemoteResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeRemoteResourceManager(
                ref AUTHZ_RPC_INIT_INFO_CLIENT pRpcInitInfo,
                out IntPtr phAuthzResourceManager
            );

            public static Int32 AuthzInitializeRemoteResourceManager(
                ref AUTHZ_RPC_INIT_INFO_CLIENT pRpcInitInfo,
                out IntPtr phAuthzResourceManager
            ) {
                if (__AuthzInitializeRemoteResourceManager(ref pRpcInitInfo, out phAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376097(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzFreeResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzFreeResourceManager(
                IntPtr hAuthzResourceManager
            );

            public static Int32 AuthzFreeResourceManager(
                IntPtr hAuthzResourceManager
            ) {
                if (__AuthzFreeResourceManager(hAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("authz.dll", EntryPoint = "AuthzModifyClaims", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzModifyClaims(
                IntPtr hAuthzClientContext,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass ClaimClass,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pClaimOperation,
                ref AUTHZ_SECURITY_ATTRIBUTES_INFORMATION pClaims
            );

            public static Int32 AuthzModifyClaims(
                IntPtr hAuthzClientContext,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass ClaimClass,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pClaimOperation,
                ref AUTHZ_SECURITY_ATTRIBUTES_INFORMATION pClaims
            ) {
                if (__AuthzModifyClaims(hAuthzClientContext, ClaimClass, pClaimOperation, ref pClaims)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

//            [DllImport("authz.dll", EntryPoint = "AuthzModifySids", SetLastError = true)]
//            [return: MarshalAs(UnmanagedType.Bool)]
//            static extern bool __AuthzModifySids(
//                IntPtr hAuthzClientContext,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass SidClass,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pSidOperations,
//                ref TOKEN_GROUPS pSids
//            );

//            public static Int32 AuthzModifySids(
//                IntPtr hAuthzClientContext,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass SidClass,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pSidOperations,
//                ref AUTHZ_SECURITY_ATTRIBUTES_INFORMATION pSids
//            ) {
//                if (__AuthzModifyClaims(hAuthzClientContext, SidClass, pSidOperations, ref pSids)) {
//                    return 0;
//                }
//                else {
//                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
//                }
//            }
        }

    }
}
"@
