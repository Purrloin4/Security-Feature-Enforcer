# SF-Enforcer Manual Mapped Driver (kdmapper Compatible) - SECURE UEFI VERSION

This is a **secure** manual mapped version of the SF-Enforcer driver that uses **direct UEFI firmware variable access** for **tamper-proof Secure Boot verification**. Designed to work with **kdmapper** while providing **non-tamper proof security verification**.

**IMPORTANT: This version uses UEFI variables directly** - providing secure, tamper-resistant verification that cannot be bypassed by registry modifications.

## Key Security Features

1. **UEFI Variable Access**: Direct firmware variable reading (tamper-proof)
2. **Non-tamper Proof**: Cannot be bypassed by registry edits or user-mode tools
3. **kdmapper Compatible**: Works reliably with manual mapping
4. **Exception Safe**: Protected against crashes during UEFI access
5. **Fallback Security**: Registry fallback if UEFI access fails (with warnings)

## Why UEFI Variables vs Registry?

### **UEFI Variables (SECURE - Used by this driver)**
- **Direct from firmware**: Reads actual UEFI Secure Boot variable
- **Tamper-proof**: Cannot be modified by malware or user tools
- **Kernel-level access**: Requires kernel privileges to read
- **Source of truth**: Actual firmware state, not a cached copy

## Security Verification Method

### **Primary Method: UEFI Variable**
```c
ExGetFirmwareEnvironmentVariable(
    L"SecureBoot",                    // Variable name
    &EFI_GLOBAL_VARIABLE,            // GUID: {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
    &secureBootValue,                // Output buffer
    &valueLength,                    // Buffer size
    NULL                             // Attributes
);
```

### **Fallback Method: Registry (with warnings)**
Only used if UEFI access fails, with clear debug warnings about reduced security.

## Files

- `driver.h` - Driver header with UEFI function declarations
- `driver.c` - **SECURE** driver implementation (UEFI variables)
- `public.h` - Shared interface definitions
- `SF-UserApp-MM.cpp` - User-mode test application
- `build.bat` - Build script
- `SF-Enforcer-MM.inf` - Driver installation file (not needed for kdmapper)

## Building

### Option 1: Using build.bat (Recommended)
```cmd
build.bat
```

### Option 2: Using Visual Studio
Build the SF-Enforcer-MM project normally.

## Usage

### 1. Load the Driver with kdmapper
```cmd
kdmapper.exe SF-Enforcer-MM.sys
```

### 2. Test the Driver
```cmd
SF-UserApp-MM.exe
```

## What This Version Tests

### SECURE BOOT VERIFICATION (UEFI METHOD)
- **Method**: Direct UEFI firmware variable access
- **Variable**: `SecureBoot` from `EFI_GLOBAL_VARIABLE`
- **Security**: Tamper-proof, cannot be bypassed
- **Fallback**: Registry check with security warnings

### NOT TESTED (Focused Version)
- HVCI Status (focused on Secure Boot only)
- DSE Status (focused on Secure Boot only)
- Test Signing (focused on Secure Boot only)
- TPM Status (focused on Secure Boot only)
- VDB Status (focused on Secure Boot only)

## Expected Output

When loaded successfully, you'll see debug output like:
```
[SF-Enforcer-MM] DriverEntry: Starting (kdmapper compatible)
[SF-Enforcer-MM] DriverEntry: Ready for Secure Boot testing
```

When testing with UEFI access:
```
[SF-Enforcer-MM] GetSecurityStatus: Starting SECURE Secure Boot check (UEFI variables)
[SF-Enforcer-MM] Secure Boot: ENABLED (verified via UEFI variable)
[SF-Enforcer-MM] UEFI SecureBoot variable value: 1
```

If UEFI access fails (fallback):
```
[SF-Enforcer-MM] ExGetFirmwareEnvironmentVariable failed: 0xC0000002
[SF-Enforcer-MM] WARNING: Falling back to registry check (less secure)
[SF-Enforcer-MM] Secure Boot: ENABLED (registry fallback - less secure)
```

## Secure Boot Testing Workflow

1. **Enable Secure Boot** in BIOS/UEFI settings
2. **Boot Windows** with Secure Boot enabled
3. **Load driver**: `kdmapper.exe SF-Enforcer-MM.sys`
4. **Test**: `SF-UserApp-MM.exe`
5. **Verify**: Should show "Secure Boot: ENABLED (verified via UEFI)"

## Security Analysis

### **High Security Scenarios**
-  UEFI variable access succeeds
-  Direct firmware verification
-  Tamper-proof results
-  Cannot be bypassed by registry edits

### **Medium Security Scenarios**
-  UEFI access fails, registry fallback used
-  Still secure but less tamper-resistant
-  Debug warnings indicate reduced security

### **Security Bypass Attempts Blocked**
-  Registry modification: Blocked (UEFI is source of truth)
-  User-mode tampering: Blocked (kernel-only access)
-  Service manipulation: Blocked (firmware-level verification)

## Viewing Debug Output

### Option 1: WinDbg (if Secure Boot disabled)
```
ed nt!Kd_DEFAULT_Mask 0xffffffff
```

### Option 2: TraceView (works with Secure Boot)
1. Open TraceView
2. Look for kernel debug output
3. Filter for "SF-Enforcer-MM"

### Option 3: DebugView (if configured)
Enable kernel capture in DebugView

## Device Interface

- **Device Name**: `\\Device\\SFEnforcerMM`
- **DOS Device**: `\\DosDevices\\SFEnforcerMM` 
- **User Access**: `\\\\.\\SFEnforcerMM`

## IOCTLs

- `IOCTL_GET_SECURITY_STATUS` (0x801) - Get secure Secure Boot status (UEFI method)

## Advantages for Secure Verification

1. **Tamper-Proof**: Direct UEFI variable access
2. **High Security**: Cannot be bypassed by registry edits
3. **kdmapper Compatible**: Works reliably with manual mapping
4. **Exception Safe**: Protected UEFI access with fallbacks
5. **Debug Friendly**: Clear security method indication
6. **Authoritative**: Direct from firmware, not cached copies

## When to Use Different Versions

### **Use This Version (UEFI) When:**
-  You need **tamper-proof** verification
-  Security is critical
-  You want to verify actual firmware state
-  Testing with Secure Boot enabled

### **Use Registry Version When:**
-  UEFI access is not available
-  Compatibility is more important than security
-  Testing in restricted environments

### **Use Full WDF Driver When:**
-  Secure Boot is disabled (development)
-  You need all security checks (HVCI, DSE, TPM, etc.)
-  Using normal driver loading (not kdmapper)
-  Production environment

## Security Notes

- **This driver is for testing purposes only**
- **Manual mapping bypasses driver signing for research/testing**
- **UEFI variable access provides the highest security level**
- **Registry fallback is provided but with security warnings**
- **Perfect for validating "Can kdmapper bypass Secure Boot?" with tamper-proof verification**

## EFI_GLOBAL_VARIABLE GUID

The Secure Boot UEFI variable uses the standard EFI Global Variable GUID:
- **GUID**: `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`
- **Variable**: `SecureBoot`
- **Type**: UINT8 (0 = Disabled, 1 = Enabled)
- **Access**: Read-only from kernel mode