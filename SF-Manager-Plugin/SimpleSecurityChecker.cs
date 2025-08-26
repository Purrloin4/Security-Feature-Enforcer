//================================================================================================================
// SimpleSecurityChecker.cs - Unity C# script for checking security status
// 
// Usage:
// 1. Copy SF-Manager-Plugin.dll to Assets/Plugins/ in your Unity project
// 2. Add this script to a GameObject in your scene
// 3. Check security status and implement your own logic based on the results
//
// Example:
//   var status = securityChecker.GetCurrentSecurityStatus();
//   if (!status.isTpmReady) {
//       ShowTPMWarning();
//   }
//================================================================================================================

using System;
using System.Runtime.InteropServices;
using UnityEngine;

namespace SFEnforcer
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    [System.Serializable]
    public struct SecurityStatus
    {
        [MarshalAs(UnmanagedType.U1)] public bool isHvciEnabled;
        [MarshalAs(UnmanagedType.U1)] public bool isSecureBootEnabled;
        [MarshalAs(UnmanagedType.U1)] public bool isTpmReady;
        [MarshalAs(UnmanagedType.U1)] public bool isDseEnabled;
        [MarshalAs(UnmanagedType.U1)] public bool isTestSigningEnabled;
        [MarshalAs(UnmanagedType.U1)] public bool isVulnerableDriverBlocklistEnabled;
        [MarshalAs(UnmanagedType.U1)] public bool isIommuEnabled;
    }

    public class SimpleSecurityChecker : MonoBehaviour
    {
        // P/Invoke declarations for SF-Manager-Plugin.dll
        [DllImport("SF-Manager-Plugin", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool InitializeSecurityDriver();

        [DllImport("SF-Manager-Plugin", CallingConvention = CallingConvention.Cdecl)]
        private static extern void CleanupSecurityDriver();

        [DllImport("SF-Manager-Plugin", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr GetLastErrorMessage();

        [DllImport("SF-Manager-Plugin", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool GetSecurityStatus(out SecurityStatus status);

        [Header("Current Security Status")]
        [SerializeField, ReadOnly] private SecurityStatus currentSecurityStatus;
        [SerializeField, ReadOnly] private bool isDriverInitialized = false;
        [SerializeField, ReadOnly] private string lastError = "";

        // Events that other systems can subscribe to
        public event System.Action<SecurityStatus> OnSecurityStatusUpdated;
        public event System.Action<string> OnDriverError;

        private void Start()
        {
            InitializeDriver();

            // Check security status every 10 seconds
            InvokeRepeating(nameof(UpdateSecurityStatus), 1f, 10f);
        }

        private void OnDestroy()
        {
            CleanupSecurityDriver();
        }

        private void InitializeDriver()
        {
            if (InitializeSecurityDriver())
            {
                isDriverInitialized = true;
                lastError = "Driver initialized successfully";
                Debug.Log("[SF-Enforcer] Security driver initialized successfully");
            }
            else
            {
                string error = GetLastErrorString();
                lastError = error;
                isDriverInitialized = false;
                Debug.LogError($"[SF-Enforcer] Failed to initialize security driver: {error}");
                OnDriverError?.Invoke(error);
            }
        }

        [ContextMenu("Update Security Status")]
        public void UpdateSecurityStatus()
        {
            if (!isDriverInitialized) return;

            if (GetSecurityStatus(out SecurityStatus status))
            {
                currentSecurityStatus = status;
                lastError = "Security status updated successfully";
                OnSecurityStatusUpdated?.Invoke(status);
            }
            else
            {
                string error = GetLastErrorString();
                lastError = error;
                Debug.LogError($"[SF-Enforcer] Failed to get security status: {error}");
                OnDriverError?.Invoke(error);
            }
        }

        private string GetLastErrorString()
        {
            IntPtr errorPtr = GetLastErrorMessage();
            return Marshal.PtrToStringAnsi(errorPtr) ?? "Unknown error";
        }

        // Public API for other game systems
        public bool IsDriverInitialized() => isDriverInitialized;
        public string GetLastError() => lastError;
        public SecurityStatus GetCurrentSecurityStatus() => currentSecurityStatus;
    }

    // Helper attribute for read-only fields in inspector
    public class ReadOnlyAttribute : PropertyAttribute { }

#if UNITY_EDITOR
    [UnityEditor.CustomPropertyDrawer(typeof(ReadOnlyAttribute))
    public class ReadOnlyDrawer : UnityEditor.PropertyDrawer
    {
        public override void OnGUI(Rect position, UnityEditor.SerializedProperty property, GUIContent label)
        {
            GUI.enabled = false;
            UnityEditor.EditorGUI.PropertyField(position, property, label, true);
            GUI.enabled = true;
        }
    }
#endif
}