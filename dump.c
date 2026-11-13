//
//  dump.c —— Nextin 配置取证（纯 C，无 SDK、无 Foundation、无 JIT）
//
//  设计约束：
//    * 不 include 任何系统头文件 —— 所有用到的符号自己声明，
//      这样可以在 Linux 上用 clang -target arm64-apple-ios 交叉编译，
//      不需要 Xcode / iPhoneOS SDK。
//    * 只调用 libSystem 里已有的函数，链接期用 -undefined dynamic_lookup。
//    * 只读内存，不修改任何代码页，因此不需要 dynamic-codesigning。
//
//  行为：加载后延迟 5 秒开始，最多扫 6 轮，把命中关键字前后的内存
//        写入 $HOME/Documents/nextin-dump.txt
//

typedef unsigned int   uint32_t;
typedef unsigned long  uintptr_t;
typedef unsigned long  size_t;
typedef int            kern_return_t;
typedef unsigned int   mach_port_t;
typedef unsigned long long mach_vm_address_t;
typedef unsigned long long mach_vm_size_t;
typedef unsigned int   vm_prot_t;
typedef int            vm_region_flavor_t;
typedef int            mach_msg_type_number_t;
typedef int            boolean_t;

#define KERN_SUCCESS 0
#define VM_PROT_READ 1
#define VM_REGION_BASIC_INFO_64 9
#define VM_REGION_BASIC_INFO_COUNT_64 9
#define MACH_PORT_NULL 0

// vm_region_basic_info_64 的布局（与 Darwin 头文件一致）
typedef struct {
    vm_prot_t   protection;
    vm_prot_t   max_protection;
    unsigned int inheritance;
    int         shared;
    int         reserved;
    unsigned long long offset;
    int         behavior;
    unsigned short user_wired_count;
} vm_region_basic_info_64;

// ---- 外部符号（libSystem 提供，运行时解析） ----
extern mach_port_t mach_task_self_;
extern kern_return_t mach_vm_region(mach_port_t, mach_vm_address_t *, mach_vm_size_t *,
                                    vm_region_flavor_t, void *, mach_msg_type_number_t *,
                                    mach_port_t *);
extern kern_return_t mach_vm_read_overwrite(mach_port_t, mach_vm_address_t, mach_vm_size_t,
                                            mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_port_deallocate(mach_port_t, mach_port_t);

extern int   open(const char *, int, ...);
extern long  write(int, const void *, size_t);
extern int   close(int);
extern char *getenv(const char *);
extern unsigned int sleep(unsigned int);
extern void *memmem(const void *, size_t, const void *, size_t);
extern int   strlen(const char *);
extern void *malloc(size_t);
extern void  free(void *);
extern int   snprintf(char *, size_t, const char *, ...);
extern int   pthread_create(unsigned long *, const void *, void *(*)(void *), void *);
extern int   pthread_detach(unsigned long);
extern int   getpid(void);

#define O_WRONLY 1
#define O_CREAT  512
#define O_APPEND 8

static int g_fd = -1;
static unsigned long g_written = 0;
static const size_t kWindow = 8192;
static const size_t kMaxOutput = 12u << 20;

static const char *kWords[] = {
    "proxy-server-nameserver",
    "nameserver-policy",
    "idle-session-timeout",
    "proxies:",
    "llguanglisf",
    "quaylight",
    0
};

static void put(const char *s) {
    if (g_fd < 0) return;
    size_t n = strlen(s);
    if (n) write(g_fd, s, n);
}

static void putln(const char *s) {
    put(s);
    put("\n");
}

// 只输出来自 [addr, addr+len) 的可打印内容
static void dump_region(mach_vm_address_t addr, size_t len) {
    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) return;
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self_, addr, len,
                                              (mach_vm_address_t)buf, &got);
    if (kr == KERN_SUCCESS && got > 0) {
        char head[96];
        snprintf(head, sizeof(head), "=== CHUNK @ 0x%llx (%llu bytes) ===",
                 (unsigned long long)addr, (unsigned long long)got);
        putln(head);
        // 逐段写，避免申请额外大缓冲
        size_t chunk = 4096;
        for (size_t off = 0; off < got; off += chunk) {
            size_t n = (got - off > chunk) ? chunk : (got - off);
            unsigned char tmp[4096];
            for (size_t i = 0; i < n; i++) {
                unsigned char b = buf[off + i];
                tmp[i] = (b == '\n' || b == '\r' || (b >= 32 && b < 127)) ? b : '.';
            }
            write(g_fd, tmp, n);
        }
        putln("\n--- end ---");
        g_written += got;
    }
    free(buf);
}

static void scan_once(int round) {
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    size_t scanned = 0, hits = 0;

    while (g_written < kMaxOutput) {
        vm_region_basic_info_64 info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        kern_return_t kr = mach_vm_region(mach_task_self_, &addr, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (void *)&info, &cnt, &obj);
        if (kr != KERN_SUCCESS) break;
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self_, obj);

        if ((info.protection & VM_PROT_READ) && size > 0 && size < (512ull << 20)) {
            const size_t chunk = 1u << 20;
            unsigned char *buf = (unsigned char *)malloc(chunk);
            if (buf) {
                mach_vm_address_t p = addr;
                mach_vm_address_t end = addr + size;
                while (p < end) {
                    size_t want = (size_t)((end - p > (mach_vm_address_t)chunk) ? chunk : (end - p));
                    mach_vm_size_t got = 0;
                    if (mach_vm_read_overwrite(mach_task_self_, p, want,
                                               (mach_vm_address_t)buf, &got) == KERN_SUCCESS && got > 0) {
                        scanned += (size_t)got;
                        for (int w = 0; kWords[w]; w++) {
                            const char *word = kWords[w];
                            size_t wl = strlen(word);
                            if (got < wl) continue;
                            unsigned char *q = buf;
                            size_t remain = (size_t)got;
                            while (remain >= wl) {
                                unsigned char *f = (unsigned char *)memmem(q, remain, word, wl);
                                if (!f) break;
                                hits++;
                                mach_vm_address_t at = p + (mach_vm_address_t)(f - buf);
                                dump_region((at > kWindow / 2) ? (at - kWindow / 2) : 0, kWindow);
                                size_t adv = (size_t)(f - q) + wl;
                                q += adv;
                                remain -= adv;
                            }
                        }
                    }
                    p += (got > 0) ? (mach_vm_address_t)got : (mach_vm_address_t)want;
                }
                free(buf);
            }
        }
        addr += size;
    }

    char line[160];
    snprintf(line, sizeof(line), "[round %d] scanned %.1f MB, hits %lu, written %.1f MB",
             round, (double)scanned / 1048576.0, (unsigned long)hits,
             (double)g_written / 1048576.0);
    putln(line);
}

static void *worker(void *arg) {
    sleep(5);
    for (int r = 1; r <= 6; r++) {
        if (g_written >= kMaxOutput) break;
        scan_once(r);
        if (g_written >= kMaxOutput) break;
        sleep(5);
    }
    putln("=== dump finished ===");
    if (g_fd >= 0) close(g_fd);
    return 0;
}

__attribute__((constructor))
static void nextin_dump_init(void) {
    const char *home = getenv("HOME");
    if (!home) return;

    char path[512];
    snprintf(path, sizeof(path), "%s/Documents/nextin-dump-%d.txt", home, getpid());
    g_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) return;

    putln("=== nextin-dump (pure C) loaded ===");

    unsigned long tid = 0;
    if (pthread_create(&tid, 0, worker, 0) == 0) {
        pthread_detach(tid);
    } else {
        worker(0);
    }
}
