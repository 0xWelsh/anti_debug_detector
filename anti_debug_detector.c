// anti_debug_detector.c
// Compile: gcc -Wall -O2 anti_debug_detector.c -o anti_debug_detector
// Usage: ./anti_debug_detector target.exe

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// Color definitions
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_BOLD    "\x1b[1m"

#define PACKED __attribute__((packed))

// Helper function to read little-endian values
static uint16_t read_le16(const uint8_t* data) {
    return data[0] | (data[1] << 8);
}

static uint32_t read_le32(const uint8_t* data) {
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

typedef struct PACKED {
    uint16_t e_magic;      // "MZ"
    uint8_t  e_cblp[58];
    uint32_t e_lfanew;     // Offset to PE header
} IMAGE_DOS_HEADER;

typedef struct PACKED {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_SIZEOF_SECTION_HEADER 40

// Common anti-debugging API functions
const char* ANTI_DEBUG_APIS[] = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "QueryPerformanceCounter",
    "rdtsc",
    "CloseHandle",
    "SetUnhandledExceptionFilter",
    "UnhandledExceptionFilter",
    "ZwQueryInformationProcess",
    "NtQueryInformationProcess",
    "GetThreadContext",
    "SetThreadContext",
    "DebugActiveProcess",
    "DebugBreak",
    "DbgUiRemoteBreakin",
    "DbgBreakPoint",
    "FindWindowA",
    "FindWindowW",
    "GetForegroundWindow",
    "Process32First",
    "Process32Next",
    "CreateToolhelp32Snapshot",
    NULL
};

// Suspicious section names that might indicate packing/protection
const char* SUSPICIOUS_SECTIONS[] = {
    ".aspack",
    ".upx",
    ".packed",
    ".enigma",
    ".themida",
    ".vmp",
    ".winlice",
    ".spack",
    ".petite",
    ".neolite",
    ".mpress",
    ".exc",
    ".ccg",
    ".yC",
    ".yP",
    ".entropy",
    ".rc4",
    ".crypt",
    ".encrypted",
    ".obfuscated",
    NULL
};

// Suspicious imports that might indicate anti-debugging
const char* SUSPICIOUS_IMPORTS[] = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", 
    "OutputDebugString",
    "GetTickCount",
    "QueryPerformanceCounter",
    "CloseHandle",  // Used in exception-based anti-debugging
    "SetUnhandledExceptionFilter",
    "UnhandledExceptionFilter",
    "ZwQueryInformationProcess",
    "NtQueryInformationProcess",
    "GetProcessHeap",  // Used in heap flag checks
    "GetVersionEx",    // Used in VM detection
    "GetSystemInfo",   // Used in VM detection
    "GlobalMemoryStatus",
    NULL
};

int check_suspicious_sections(const uint8_t* data, uint32_t file_size, uint32_t pe_offset) {
    uint32_t file_hdr_offset = pe_offset + 4;
    if (file_hdr_offset + sizeof(IMAGE_FILE_HEADER) > file_size) return 0;
    
    uint16_t num_sections = read_le16(data + file_hdr_offset + 2);
    uint16_t opt_header_size = read_le16(data + file_hdr_offset + 16);
    uint32_t sec_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) + opt_header_size;
    
    int suspicious_count = 0;
    
    for (int i = 0; i < num_sections; i++) {
        uint8_t* sec = (uint8_t*)(data + sec_offset + i * IMAGE_SIZEOF_SECTION_HEADER);
        char name[9];
        memcpy(name, sec, 8);
        name[8] = '\0';
        
        // Check for empty section names (suspicious)
        if (strlen(name) == 0) {
            printf(COLOR_YELLOW "  ⚠ Empty section name\n" COLOR_RESET);
            suspicious_count++;
            continue;
        }
        
        // Check against known suspicious section names
        for (int j = 0; SUSPICIOUS_SECTIONS[j] != NULL; j++) {
            if (strstr(name, SUSPICIOUS_SECTIONS[j])) {
                printf(COLOR_RED "  ⚠ Known packer section: %s\n" COLOR_RESET, name);
                suspicious_count++;
                break;
            }
        }
        
        // Check section characteristics for RWX (common in packed code)
        uint32_t characteristics = read_le32(sec + 36);
        if ((characteristics & 0xE0000000) == 0xE0000000) { // RWX
            printf(COLOR_RED "  ⚠ RWX section detected: %s\n" COLOR_RESET, name);
            suspicious_count++;
        }
        
        // Check for unusually high raw/virtual size ratio
        uint32_t raw_size = read_le32(sec + 16);
        uint32_t virt_size = read_le32(sec + 8);
        if (raw_size > 0 && virt_size > raw_size * 10) {
            printf(COLOR_YELLOW "  ⚠ High virtual/raw size ratio in %s (V:0x%x R:0x%x)\n" COLOR_RESET, 
                   name, virt_size, raw_size);
            suspicious_count++;
        }
    }
    
    return suspicious_count;
}

int check_tls_entry(const uint8_t* data, uint32_t file_size, uint32_t pe_offset) {
    // TLS (Thread Local Storage) is often used for early anti-debugging
    uint32_t opt_hdr_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    
    // Check DataDirectory[9] which is TLS
    uint32_t tls_rva = read_le32(data + opt_hdr_offset + 96 + 8);  // 96 = DataDirectory start, 8 = TLS index
    uint32_t tls_size = read_le32(data + opt_hdr_offset + 96 + 12);
    
    if (tls_rva != 0 && tls_size != 0) {
        printf(COLOR_RED "  ⚠ TLS entry detected (common in protected executables)\n" COLOR_RESET);
        return 1;
    }
    
    return 0;
}

int check_imports_for_anti_debug(const uint8_t* data, uint32_t file_size, uint32_t pe_offset) {
    uint32_t opt_hdr_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    
    // Import table is DataDirectory[1]
    uint32_t import_rva = read_le32(data + opt_hdr_offset + 96 + 8);
    uint32_t import_size = read_le32(data + opt_hdr_offset + 96 + 12);
    
    if (import_rva == 0) return 0;
    
    // Convert RVA to file offset (simplified - in real implementation, need proper RVA to offset conversion)
    uint32_t import_offset = import_rva; // This is simplified
    
    int anti_debug_count = 0;
    
    // Simplified import table parsing - in real implementation, you'd properly parse IMAGE_IMPORT_DESCRIPTOR
    // Here we'll just search for suspicious strings in the import section
    
    for (int i = 0; SUSPICIOUS_IMPORTS[i] != NULL; i++) {
        const char* api_name = SUSPICIOUS_IMPORTS[i];
        if (import_offset < file_size - strlen(api_name)) {
            // Search for the API name in the import table area
            for (uint32_t j = import_offset; j < import_offset + import_size - strlen(api_name); j++) {
                if (memcmp(data + j, api_name, strlen(api_name)) == 0) {
                    printf(COLOR_RED "  ⚠ Anti-debug API found: %s\n" COLOR_RESET, api_name);
                    anti_debug_count++;
                    break;
                }
            }
        }
    }
    
    return anti_debug_count;
}

int check_timing_apis(const uint8_t* data, uint32_t file_size) {
    // Search for timing-related API strings in the entire file
    const char* timing_apis[] = {
        "GetTickCount",
        "QueryPerformanceCounter",
        "timeGetTime",
        "GetSystemTime",
        "GetLocalTime",
        "rdtsc",
        NULL
    };
    
    int timing_count = 0;
    
    for (int i = 0; timing_apis[i] != NULL; i++) {
        const char* api_name = timing_apis[i];
        size_t api_len = strlen(api_name);
        
        for (uint32_t j = 0; j < file_size - api_len; j++) {
            if (memcmp(data + j, api_name, api_len) == 0) {
                printf(COLOR_YELLOW "  ⚠ Timing API found: %s\n" COLOR_RESET, api_name);
                timing_count++;
                break;
            }
        }
    }
    
    return timing_count;
}

int check_debug_strings(const uint8_t* data, uint32_t file_size) {
    // Search for debug string APIs
    const char* debug_strings[] = {
        "OutputDebugStringA",
        "OutputDebugStringW",
        "DbgPrint",
        "DbgPrompt",
        NULL
    };
    
    int debug_string_count = 0;
    
    for (int i = 0; debug_strings[i] != NULL; i++) {
        const char* api_name = debug_strings[i];
        size_t api_len = strlen(api_name);
        
        for (uint32_t j = 0; j < file_size - api_len; j++) {
            if (memcmp(data + j, api_name, api_len) == 0) {
                printf(COLOR_YELLOW "  ⚠ Debug string API found: %s\n" COLOR_RESET, api_name);
                debug_string_count++;
                break;
            }
        }
    }
    
    return debug_string_count;
}

int check_exception_apis(const uint8_t* data, uint32_t file_size) {
    // Search for exception-related APIs used in anti-debugging
    const char* exception_apis[] = {
        "SetUnhandledExceptionFilter",
        "UnhandledExceptionFilter", 
        "IsBadReadPtr",
        "IsBadWritePtr",
        "IsBadCodePtr",
        NULL
    };
    
    int exception_count = 0;
    
    for (int i = 0; exception_apis[i] != NULL; i++) {
        const char* api_name = exception_apis[i];
        size_t api_len = strlen(api_name);
        
        for (uint32_t j = 0; j < file_size - api_len; j++) {
            if (memcmp(data + j, api_name, api_len) == 0) {
                printf(COLOR_RED "  ⚠ Exception-based anti-debug API: %s\n" COLOR_RESET, api_name);
                exception_count++;
                break;
            }
        }
    }
    
    return exception_count;
}

int check_direct_anti_debug_calls(const uint8_t* data, uint32_t file_size) {
    // Search for direct anti-debug API calls
    const char* direct_apis[] = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "ZwQueryInformationProcess",
        "NtQueryInformationProcess",
        NULL
    };
    
    int direct_count = 0;
    
    for (int i = 0; direct_apis[i] != NULL; i++) {
        const char* api_name = direct_apis[i];
        size_t api_len = strlen(api_name);
        
        for (uint32_t j = 0; j < file_size - api_len; j++) {
            if (memcmp(data + j, api_name, api_len) == 0) {
                printf(COLOR_RED "  ⚠ Direct anti-debug API: %s\n" COLOR_RESET, api_name);
                direct_count++;
                break;
            }
        }
    }
    
    return direct_count;
}

int analyze_anti_debug(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        perror("fstat");
        fclose(f);
        return -1;
    }
    size_t file_size = st.st_size;

    if (file_size == 0) {
        fprintf(stderr, "File is empty\n");
        fclose(f);
        return -1;
    }

    uint8_t* data = malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(f);
        return -1;
    }

    if (fread(data, 1, file_size, f) != file_size) {
        fprintf(stderr, "fread failed\n");
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);

    printf(COLOR_BOLD "=== Anti-Debugging Analysis: %s ===\n\n" COLOR_RESET, filepath);

    // Check DOS header
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "File too small for DOS header\n");
        free(data);
        return -1;
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != 0x5A4D) {
        fprintf(stderr, "Invalid DOS header\n");
        free(data);
        return -1;
    }

    uint32_t pe_offset = read_le32((uint8_t*)&dos->e_lfanew);
    if (pe_offset == 0 || pe_offset > file_size - 4) {
        fprintf(stderr, "Invalid PE offset\n");
        free(data);
        return -1;
    }

    uint32_t sig = read_le32(data + pe_offset);
    if (sig != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE signature\n");
        free(data);
        return -1;
    }

    int total_suspicious = 0;
    
    printf(COLOR_CYAN "Scanning for anti-debugging techniques...\n\n" COLOR_RESET);
    
    // Perform various checks
    total_suspicious += check_suspicious_sections(data, file_size, pe_offset);
    total_suspicious += check_tls_entry(data, file_size, pe_offset);
    total_suspicious += check_direct_anti_debug_calls(data, file_size);
    total_suspicious += check_exception_apis(data, file_size);
    total_suspicious += check_timing_apis(data, file_size);
    total_suspicious += check_debug_strings(data, file_size);
    
    printf(COLOR_CYAN "\n=== RESULTS ===\n" COLOR_RESET);
    printf("Total suspicious indicators found: %d\n\n", total_suspicious);
    
    // Final determination
    if (total_suspicious >= 3) {
        printf(COLOR_BOLD COLOR_RED "POSITIVE - Strong evidence of anti-debugging techniques\n" COLOR_RESET);
        printf("The file likely contains multiple anti-debugging protections.\n");
    } else if (total_suspicious >= 1) {
        printf(COLOR_BOLD COLOR_YELLOW "SUSPICIOUS - Some anti-debugging indicators found\n" COLOR_RESET);
        printf("The file may contain basic anti-debugging measures.\n");
    } else {
        printf(COLOR_BOLD COLOR_GREEN "NEGATIVE - No significant anti-debugging detected\n" COLOR_RESET);
        printf("The file appears to be unprotected against debugging.\n");
    }
    
    free(data);
    return total_suspicious;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }
    
    int result = analyze_anti_debug(argv[1]);
    
    if (result >= 3) {
        return 2; // POSITIVE
    } else if (result >= 1) {
        return 1; // SUSPICIOUS  
    } else {
        return 0; // NEGATIVE
    }
}