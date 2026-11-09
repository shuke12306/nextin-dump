//
//  dump.m —— Nextin 配置取证（纯读取，不需要 JIT / dynamic-codesigning）
//
//  原理：只做三件事
//    1. 遍历自己的地址空间（vm_region_64）
//    2. 用 vm_read_overwrite 分块读出来
//    3. memmem 搜关键字，命中就把前后各 8KB 写进 Documents/nextin-dump.txt
//
//  编译：见 .github/workflows/build.yml
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <pthread.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#include <dispatch/dispatch.h>

static NSString *gOutPath = nil;
static NSLock *gLock = nil;
static NSMutableSet *gSeen = nil;      // 已导出的地址，避免重复
static unsigned long gWritten = 0;

static const char *kWords[] = {
    "idle-session-timeout",   // AnyTLS 独有，误报最低
    "anytls",
    "proxies:",
    "llguanglisf",
    "quaylight",
    NULL
};

static const size_t kWindow = 8192;        // 命中点前后各取的字节
static const size_t kMaxOutput = 12 << 20; // 输出上限 12MB，防失控

static void logLine(NSString *s) {
    if (!gOutPath) return;
    @autoreleasepool {
        NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:gOutPath]) {
            [d writeToFile:gOutPath atomically:NO];
            return;
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gOutPath];
        if (!fh) return;
        @try {
            [fh seekToEndOfFile];
            [fh writeData:d];
            [fh closeFile];
        } @catch (NSException *e) {
        }
    }
}

// 把一段字节转成可读文本：不可打印字符换成 '.'
static NSString *sanitize(const uint8_t *buf, size_t len) {
    NSMutableData *out = [NSMutableData dataWithCapacity:len];
    for (size_t i = 0; i < len; i++) {
        uint8_t b = buf[i];
        if (b == '\n' || b == '\r' || (b >= 32 && b < 127)) {
            [out appendBytes:&b length:1];
        } else {
            uint8_t dot = '.';
            [out appendBytes:&dot length:1];
        }
    }
    return [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] ?: @"";
}

static void dumpAround(vm_address_t task, vm_address_t hit, const char *word) {
    vm_address_t start = (hit > kWindow) ? (hit - kWindow / 2) : 0;
    uint8_t *buf = malloc(kWindow);
    if (!buf) return;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(task, start, kWindow, (vm_address_t)buf, &got);
    if (kr == KERN_SUCCESS && got > 0) {
        NSString *text = sanitize(buf, got);
        if ([text containsString:[NSString stringWithUTF8String:word]]) {
            @synchronized (gSeen) {
                NSNumber *key = @(hit);
                if (![gSeen containsObject:key]) {
                    [gSeen addObject:key];
                    NSString *head = [NSString stringWithFormat:
                        @"=== HIT %s @ 0x%llx ===\n", word, (unsigned long long)hit];
                    logLine(head);
                    logLine(text);
                    logLine(@"--- end ---");
                    gWritten += got;
                }
            }
        }
    }
    free(buf);
}

static void scanOnce(int round) {
    mach_port_t task = mach_task_self();
    vm_address_t addr = 0;
    vm_size_t regionSize = 0;
    size_t scanned = 0, hits = 0;

    while (gWritten < kMaxOutput) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName = MACH_PORT_NULL;
        kern_return_t kr = vm_region_64(task, &addr, &regionSize,
                                        VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &count, &objectName);
        if (kr != KERN_SUCCESS) break;
        if (objectName != MACH_PORT_NULL) mach_port_deallocate(task, objectName);

        if ((info.protection & VM_PROT_READ) && regionSize > 0 && regionSize < (512ULL << 20)) {
            const size_t chunk = 1 << 20;
            uint8_t *buf = malloc(chunk);
            if (buf) {
                vm_address_t p = addr;
                vm_address_t end = addr + regionSize;
                while (p < end) {
                    size_t want = (size_t)MIN(chunk, end - p);
                    vm_size_t got = 0;
                    kr = vm_read_overwrite(task, p, want, (vm_address_t)buf, &got);
                    if (kr == KERN_SUCCESS && got > 0) {
                        scanned += got;
                        for (int w = 0; kWords[w]; w++) {
                            const char *word = kWords[w];
                            size_t wl = strlen(word);
                            if (got < wl) continue;
                            uint8_t *q = buf;
                            size_t remain = got;
                            while (remain >= wl) {
                                uint8_t *found = memmem(q, remain, word, wl);
                                if (!found) break;
                                hits++;
                                dumpAround(task, p + (found - buf), word);
                                size_t adv = (found - q) + wl;
                                q += adv; remain -= adv;
                            }
                        }
                    }
                    p += got > 0 ? got : want;
                }
                free(buf);
            }
        }
        addr += regionSize;
    }

    logLine([NSString stringWithFormat:@"[round %d] 扫描 %.1f MB，命中 %zu 次，累计导出 %.1f MB",
             round, scanned / 1048576.0, hits, gWritten / 1048576.0]);
}

__attribute__((constructor))
static void nextin_dump_init(void) {
    @autoreleasepool {
        gLock = [NSLock new];
        gSeen = [NSMutableSet new];

        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = paths.firstObject ?: @"/tmp";
        gOutPath = [docs stringByAppendingPathComponent:@"nextin-dump.txt"];

        NSString *banner = [NSString stringWithFormat:
            @"=== nextin-dump loaded, pid=%d, path=%@ ===",
            getpid(), gOutPath];
        logLine(banner);

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            // 等 App 把配置读进内存再开始
            [NSThread sleepForTimeInterval:5.0];
            for (int round = 1; round <= 6; round++) {
                @autoreleasepool {
                    scanOnce(round);
                }
                if (gWritten >= kMaxOutput) break;
                [NSThread sleepForTimeInterval:5.0];
            }
            logLine(@"=== dump finished ===");
        });
    }
}
