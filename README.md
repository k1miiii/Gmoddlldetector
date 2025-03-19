# AntiCheat DLL with Module Signature & Manual Mapping Detection

This project implements an anti-cheat DLL that combines two detection techniques:
# ALL CODE IS WORK IN PROGRESS , IT ONLY DETECTS SIMPLE INJECTION NO MANUAL MAPPING
<s>1. **Digital Signature Verification:**  
   Checks loaded modules against an allowed certificate serial number. Only modules signed with the approved certificate (e.g., serial number `267a74977c25c65a60d8e2150343f787`) pass the check.

2. **Manual Mapping Detection:**  
   Scans process memory for valid Portable Executable (PE) headers to detect modules injected via manual mapping that bypass traditional Windows loader APIs.
--- **TEXT** ---

## Features

- **Digital Signature Verification:**  
  - Uses Windows API functions (*WinVerifyTrust*, *CryptQueryObject*, etc.) to verify module signatures.
  - Extracts the certificate's serial number and whitelists modules matching a specified serial number.

- **Manual Mapping Detection:**  
  - Scans process memory using `VirtualQuery` for regions with executable permissions.
  - Validates memory regions by checking for the "MZ" and "PE\0\0" signatures, flagging potentially manually mapped modules.

- **Logging:**  
  - Detected modules failing the signature check are logged to `DetectedDLLs.txt`.
  - Suspicious memory regions that may indicate manually mapped modules are logged to `DetectedManualMappedModules.txt`.

- **Periodic Checks:**  
  - A dedicated thread runs periodic scans (every 5 seconds) to continuously monitor for suspicious modules and memory regions.

## Requirements

- **Operating System:** Windows  
- **Development Environment:** Visual Studio or any C++ compiler that supports Windows API development.
- **Libraries:**  
  - `wintrust.lib`
  - `crypt32.lib`
- **Headers:**  
  - `<windows.h>`
  - `<wincrypt.h>`
  - `<softpub.h>`
  - `<wintrust.h>`
  - `<tlhelp32.h>`

## Building the DLL

1. **Clone or Download the Project:**  
   Obtain the source code from your repository.

2. **Configure Your Project:**  
   - Include the required libraries in your project settings.
   - Ensure that the include paths point to the Windows SDK headers.

3. **Compile:**  
   Build the project as a DLL in your preferred configuration (Debug/Release).

## Integration

- **Injection:**  
  Inject the compiled DLL into your target process (e.g., using a custom injector or any suitable DLL injection method).

- **Usage:**  
  Once injected, the DLL will automatically:
  - Enumerate loaded modules.
  - Verify each module's digital signature.
  - Scan the process memory for manually mapped modules.
  - Log any suspicious modules or regions to text files in the same folder as the DLL.

- **Configuration:**  
  To change the allowed certificate serial number, modify the `allowedSerialNumber` variable in the `IsModuleAllowedBySignature` function.

## Limitations & Considerations

- **Manual Mapping Evasion:**  
  Advanced cheat implementations might employ further obfuscation techniques to evade memory scans. The provided memory scan uses basic heuristics; additional checks may be needed for production use.

- **False Positives:**  
  Memory scanning can yield false positives. It is recommended to refine the heuristics based on your application's context.

- **Performance Impact:**  
  Scanning the entire process memory can be resource-intensive. Adjust the scan frequency as necessary.</s>

## License

This project is provided "as-is", without any warranty. Use at your own risk. See the [LICENSE](LICENSE) file for more details (if applicable).

## Acknowledgments

Inspired by [MapDetection](https://github.com/vmcall/MapDetection) for manual mapping detection techniques.

## Contact

For questions, improvements, or issues, please open an issue in the repository or contact the project maintainer.

