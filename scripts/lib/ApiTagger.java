package lib;

import java.util.*;

/**
 * Manages suspicious API signatures, MITRE ATT&CK technique tags, and threat scoring weights.
 */
public class ApiTagger {

    public static class ApiTag {
        public final String technique;
        public final String category;
        public final int weight;

        public ApiTag(String technique, String category, int weight) {
            this.technique = technique;
            this.category = category;
            this.weight = weight;
        }
    }

    private static final Map<String, ApiTag> API_MAP = new HashMap<>();

    static {
        // Process Injection (T1055)
        add("VirtualAlloc", "T1055", "Memory Allocation / Injection", 15);
        add("VirtualProtect", "T1055", "Memory Permission Change", 15);
        add("VirtualAllocEx", "T1055", "Process Injection", 20);
        add("VirtualProtectEx", "T1055", "Process Injection", 15);
        add("WriteProcessMemory", "T1055", "Process Injection", 20);
        add("CreateRemoteThread", "T1055", "Process Injection", 25);
        add("QueueUserAPC", "T1055", "Process Injection", 15);
        add("SetThreadContext", "T1055", "Process Injection", 20);
        add("NtCreateThreadEx", "T1055", "Process Injection", 25);
        add("mprotect", "T1055", "Memory Protection Mod", 15);

        // Process Hollowing (T1055.009)
        add("NtMapViewOfSection", "T1055.009", "Process Hollowing", 20);
        add("NtUnmapViewOfSection", "T1055.009", "Process Hollowing", 20);
        add("ptrace", "T1055.009", "Process Hollowing / Tracing", 15);

        // Process / Command Execution (T1059)
        add("CreateProcessA", "T1059", "Process Creation", 15);
        add("CreateProcessW", "T1059", "Process Creation", 15);
        add("ShellExecuteA", "T1059", "Command / Process Execution", 15);
        add("ShellExecuteW", "T1059", "Command / Process Execution", 15);
        add("WinExec", "T1059", "Command Execution", 20);
        add("system", "T1059", "Command Execution", 15);
        add("execve", "T1059", "Process Execution", 15);
        add("popen", "T1059", "Pipe Execution", 15);

        // Discovery (T1016, T1057, T1082)
        add("GetIpAddrTable", "T1016", "Network Config Discovery", 10);
        add("GetAdaptersInfo", "T1016", "Network Adapter Discovery", 10);
        add("GetModuleInformation", "T1057", "Process Discovery", 10);
        add("EnumProcesses", "T1057", "Process Discovery", 10);
        add("Process32First", "T1057", "Process Discovery", 15);
        add("Process32Next", "T1057", "Process Discovery", 10);
        add("GetSystemInfo", "T1082", "System Info Discovery", 5);

        // Persistence & Autostart (T1547)
        add("RegSetValueExA", "T1547", "Persistence (Registry)", 15);
        add("RegSetValueExW", "T1547", "Persistence (Registry)", 15);
        add("CreateServiceA", "T1547", "Persistence (Service)", 20);
        add("CreateServiceW", "T1547", "Persistence (Service)", 20);
        add("OpenSCManagerA", "T1547", "Service Control", 10);
        add("OpenSCManagerW", "T1547", "Service Control", 10);

        // Debugger Evasion / Anti-Analysis (T1622)
        add("IsDebuggerPresent", "T1622", "Debugger Evasion", 15);
        add("CheckRemoteDebuggerPresent", "T1622", "Debugger Evasion", 15);
        add("NtQueryInformationProcess", "T1622", "Defense Evasion", 20);
        add("OutputDebugStringA", "T1622", "Anti-Debug / Logging", 5);
        add("OutputDebugStringW", "T1622", "Anti-Debug / Logging", 5);

        // Credential Dumping (T1003)
        add("MiniDumpWriteDump", "T1003", "Credential Dumping", 30);
        add("SamIConnect", "T1003", "Credential Dumping (SAM)", 30);
        add("LsaEnumerateLogonSessions", "T1003", "Credential Dumping (LSA)", 25);

        // Dynamic API Resolution (T1027)
        add("GetModuleHandleA", "T1027", "Dynamic API Resolution", 5);
        add("GetModuleHandleW", "T1027", "Dynamic API Resolution", 5);
        add("LoadLibraryA", "T1027", "Dynamic API Resolution", 10);
        add("LoadLibraryW", "T1027", "Dynamic API Resolution", 10);
        add("LoadLibraryExA", "T1027", "Dynamic API Resolution", 10);
        add("LoadLibraryExW", "T1027", "Dynamic API Resolution", 10);
        add("GetProcAddress", "T1027", "Dynamic API Resolution", 10);
        add("dlsym", "T1027", "Dynamic API Resolution", 10);
        add("dlopen", "T1027", "Dynamic API Resolution", 10);

        // Network Communication (T1071, T1105)
        add("WSAStartup", "T1071", "Network Socket Init", 10);
        add("connect", "T1071", "Network Connect", 15);
        add("InternetOpenA", "T1071", "HTTP / C2 Communication", 15);
        add("InternetOpenW", "T1071", "HTTP / C2 Communication", 15);
        add("InternetConnectA", "T1071", "HTTP / C2 Communication", 15);
        add("InternetConnectW", "T1071", "HTTP / C2 Communication", 15);
        add("HttpOpenRequestA", "T1071", "HTTP / C2 Communication", 15);
        add("HttpOpenRequestW", "T1071", "HTTP / C2 Communication", 15);
        add("URLDownloadToFileA", "T1105", "Remote Ingress Download", 20);
        add("URLDownloadToFileW", "T1105", "Remote Ingress Download", 20);

        // Native API (T1106)
        add("NtAllocateVirtualMemory", "T1106", "Native Syscall", 15);
        add("NtWriteVirtualMemory", "T1106", "Native Syscall", 20);
        add("NtProtectVirtualMemory", "T1106", "Native Syscall", 15);
    }

    private static void add(String func, String technique, String category, int weight) {
        API_MAP.put(func, new ApiTag(technique, category, weight));
    }

    public static ApiTag getTag(String functionName) {
        if (functionName == null) return null;
        ApiTag tag = API_MAP.get(functionName);
        if (tag == null && (functionName.endsWith("A") || functionName.endsWith("W"))) {
            tag = API_MAP.get(functionName.substring(0, functionName.length() - 1));
        }
        return tag;
    }

    public static boolean isSuspicious(String functionName) {
        return getTag(functionName) != null;
    }

    public static Map<String, ApiTag> getAllTags() {
        return Collections.unmodifiableMap(API_MAP);
    }
}
