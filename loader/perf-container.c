#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <hugetlbfs.h>
#include <string.h>

struct vcpu {
    char *run;
    int fd;
};

struct mem_slot {
    int used;
};

struct system {
    size_t host_page_size, vcpu_region_size;

    int kvm, nr_memslots;
    int vm;
    struct vcpu vcpu;
    struct mem_slot *mem_slots;
};

static void
dump_reg1(const char *tag, __u64 val)
{
    printf("%10s:%22lld(%16llx)\n",
           tag,
           (long long)val,
           (long long)val);
}

static void
dump_seg1(const char *tag, struct kvm_segment *seg)
{
    printf("%10s: base=%16llx, limit=%8x, sel=%8d, type=%4d\n",
           tag,
           (unsigned long long)seg->base,
           (int)seg->limit,
           (int)seg->selector,
           (int)seg->type
        );
}


static void
dump_dt(const char *tag, struct kvm_dtable *dt)
{
    printf("%10s: base=%16llx, limit=%8x\n",
           tag,
           (long long)dt->base,
           (int)dt->limit);
}



static int
alloc_slot(struct system *sys) {
    for (int i=0; i<sys->nr_memslots; i++) {
        if (! sys->mem_slots[i].used) {
            sys->mem_slots[i].used = 1;
            return i;
        }
    }

    return -1;
}

static void *
alloc_page(struct system *sys, int num_page)
{
    char *ret;
    size_t alloc_size = sys->host_page_size * num_page;

    ret = mmap(0, alloc_size, PROT_READ|PROT_WRITE,
               MAP_ANONYMOUS|MAP_PRIVATE|MAP_HUGETLB, 0, 0);
    if (ret == MAP_FAILED) {
        ret = mmap(0, alloc_size, PROT_READ|PROT_WRITE,
                   MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
        if (ret == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }

        {
            static int warn = 0;
            if (warn == 0) {
                fprintf(stderr,
                        "warning: Mapping %zd MB page is failed. If you need more precise test, try to increase /proc/sys/vm/nr_hugepages\n",
                        (sys->host_page_size/(1024*1024))
                    );
                warn = 1;
            }
        }
    }

    return ret;
}

static void
setup_vcpu(struct system *sys,
           struct vcpu *vcpu,
           __u64 entry)
{
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int fd = vcpu->fd;
    ioctl(fd, KVM_GET_REGS, &regs, NULL);

    regs.rip = entry;
    regs.rsp = 0x00600000;

    ioctl(fd, KVM_SET_REGS, &regs, NULL);

    ioctl(fd, KVM_GET_SREGS, &sregs, NULL);

    sregs.cs.base = 0;
    sregs.cs.limit = ~0;
    sregs.cs.g = 1;
    sregs.ds.base = 0;
    sregs.ds.limit = ~0;
    sregs.ds.g = 1;
    sregs.ss.base = 0;
    sregs.ss.limit = ~0;
    sregs.ss.g = 1;

    sregs.cs.db = 0;
    sregs.ss.db = 0;
    sregs.ds.db = 0;

    sregs.cs.l = 1;
    sregs.ds.l = 1;
    sregs.ss.l = 1;

    sregs.cr0 |= 0x80000001;    /* paging | protect */
    sregs.cr3 = 0x00200000;     /* pml4 */
    sregs.cr4 |= 1<<5;          /* PAE */
    sregs.efer |= 1<<8;         /* LME */

    ioctl(fd, KVM_SET_SREGS, &sregs, NULL);


}

static void
setup_initial_page(struct system *sys,
                   char *initial_page,
                   size_t initial_page_size)
{
    /*
     *                  ---------------
     *                   elf segment
     * (4MB) 0x00400000 ---------------
     *
     *
     *
     *
     *       0x00202000 (pd)            4KB  pd[0] = 0, pd[1] = 2MB, pd[2] = 3MB
     *       0x00201000 (pdp)           4KB
     *                  (pml4)          4KB
     * (2MB) 0x00200000 ----------------
     *                   unmapped
     *       0x00000000 ----------------
     */

    struct kvm_userspace_memory_region mem = {0};
    mem.slot = alloc_slot(sys);
    mem.flags = 0;
    mem.guest_phys_addr = 2*1024*1024;
    mem.memory_size = initial_page_size;
    mem.userspace_addr = (__u64)initial_page;

    int r = ioctl(sys->vm, KVM_SET_USER_MEMORY_REGION, &mem, NULL);
    if (r == -1) {
        perror("KVM_SET_USER_MEMORY_REGION");
        exit(1);
    }

    /* init pml4 */
    __u64 *table = (__u64*)initial_page;

    for (int i=0; i<2048; i++) {
        table[i] = 0;
    }
    table[0] = 0x7 | 0x00201000; /* point to pdp */

    /* init pdp */
    table = (__u64*)(initial_page + 0x1000);
    for (int i=0; i<2048; i++) {
        table[i] = 0;
    }
    table[0] = 0x7 | 0x00202000; /* point to pd */

    /* init pd */
    table = (__u64*)(initial_page + 0x2000);
    for (int i=0; i<2048; i++) {
        table[i] = 0;
    }
    table[0] = (1<<7) | 0x7 | 0x00000000; /* 2MB page, point to 0 */
    table[1] = (1<<7) | 0x7 | 0x00200000; /* 2MB page, point to page table */
    table[2] = (1<<7) | 0x7 | 0x00400000; /* 2MB page, point to loaded executable */

    /* gdt */
    __u32 *table32 = (__u32*)(initial_page + 0x3000);
    table32[0] = 0;
    table32[1] = 1;
    table32[2] = 0;
    table32[3] = 1;
}


static void
dump_regs(struct vcpu *vcpu)
{
    int fd = vcpu->fd;
    struct kvm_regs regs;
    ioctl(fd, KVM_GET_REGS, &regs, NULL);

    dump_reg1("rip", regs.rip);
    dump_reg1("rflags", regs.rflags);

    dump_reg1("rax", regs.rax);
    dump_reg1("rbx", regs.rbx);
    dump_reg1("rcx", regs.rcx);
    dump_reg1("rdx", regs.rdx);

    dump_reg1("rsi", regs.rsi);
    dump_reg1("rdi", regs.rdi);
    dump_reg1("rsp", regs.rsp);
    dump_reg1("rbp", regs.rbp);

    dump_reg1("r8", regs.r8);
    dump_reg1("r9", regs.r9);
    dump_reg1("r10", regs.r10);
    dump_reg1("r11", regs.r11);

    dump_reg1("r12", regs.r12);
    dump_reg1("r13", regs.r13);
    dump_reg1("r14", regs.r14);
    dump_reg1("r15", regs.r15);

    struct kvm_sregs sregs;
    ioctl(fd, KVM_GET_SREGS, &sregs, NULL);

    dump_reg1("cr0", sregs.cr0);
    dump_reg1("cr2", sregs.cr2);
    dump_reg1("cr3", sregs.cr3);
    dump_reg1("cr4", sregs.cr4);
    dump_reg1("cr8", sregs.cr8);
    dump_reg1("efer", sregs.efer);
    dump_reg1("apic_base", sregs.apic_base);

    dump_seg1("cs", &sregs.cs);
    dump_seg1("ds", &sregs.ds);
    dump_seg1("es", &sregs.es);
    dump_seg1("fs", &sregs.fs);
    dump_seg1("gs", &sregs.gs);
    dump_seg1("ss", &sregs.ss);
    dump_seg1("tr", &sregs.tr);
    dump_seg1("ldt", &sregs.ldt);

    dump_dt("gdt", &sregs.gdt);
    dump_dt("idt", &sregs.idt);
}

static void
capability_test(int fd, int cap, const char *tag)
{
    int r = ioctl(fd, KVM_CHECK_EXTENSION, (void*)(uintptr_t)cap);
    if (!r) {
        fprintf(stderr, "kvm does not support %s\n", tag);
        exit(1);
    }
}

static void
usage(const char *argv0)
{
    printf("usage : %s elf_file\n", argv0);
    exit(0);
}

static void load_segment(char *guest_page,
                         Elf64_Phdr *phdr,
                         char *elf)
{
    char *guest_start = guest_page + phdr->p_vaddr;
    char *src_start = elf + phdr->p_offset;

    __u64 free_start = 0x00400000;
    __u64 free_end = 0x00600000;

    __u64 elf_load_start = (__u64)phdr->p_vaddr;
    __u64 elf_load_end = (__u64)phdr->p_vaddr + phdr->p_filesz;

    if ((elf_load_start >= free_start) &&
        (elf_load_start < free_end) &&
        (elf_load_end >= free_start) &&
        (elf_load_end < free_end))
    {
        /* ok */
    } else {
        fprintf(stderr,
                "mapping elf is failed. address out of range. : (%16llx-%16llx)\n",
                (long long)phdr->p_vaddr,
                (long long)phdr->p_vaddr+phdr->p_filesz);
        exit(1);
    }

    memcpy(guest_start, src_start, phdr->p_filesz);
}

int
main(int argc, char **argv)
{
    struct system system;
    system.host_page_size = 2048 * 1024;

    while (1) {
        static struct option long_options[] = {
            {"host-page-size", required_argument, 0, 0},
        };

        int option_index;
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            switch (option_index) {
            case 0:
                //host_page_size = atol(optarg);
                break;
            default:
                break;
            }
            break;

        case '?':
            usage(argv[0]);
            break;

        default:
            break;
        }
    }

    system.kvm = open("/dev/kvm", O_RDWR);
    if (system.kvm == -1) {
        perror("/dev/kvm");
        return 1;
    }

    int ver, num_msr;
    struct kvm_msr_list msr_list0, *msr_list;

    ver = ioctl(system.kvm, KVM_GET_API_VERSION, NULL);
    if (ver < 12) {
        fprintf(stderr, "kvm is too old (version=%d).\n", ver);
        return 1;
    }

    capability_test(system.kvm, KVM_CAP_USER_MEMORY, "KVM_CAP_USER_MEMORY");
    system.nr_memslots = ioctl(system.kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS, NULL);
    if (system.nr_memslots < 0) {
        perror("KVM_CAP_NR_MEMSLOTS");
        return 1;
    }
    if (system.nr_memslots <= 3) {
        fprintf(stderr, "too few mem slots (%d)\n", system.nr_memslots);
        return 1;
    }

    system.mem_slots = malloc(sizeof(struct mem_slot) * system.nr_memslots);
    for (int i=0; i<system.nr_memslots; i++) {
        system.mem_slots[i].used = 0;
    }

    {
        int num_page_size = getpagesizes(0,0);
        long *page_sizes = malloc(sizeof(long) * num_page_size);
        int supported = 0;

        getpagesizes(page_sizes, num_page_size);

        for (int i=0; i<num_page_size; i++) {
            if (page_sizes[i] == system.host_page_size) {
                supported = 1;
                break;
            }
        }

        free(page_sizes);

        if (!supported) {
            fprintf(stderr, "%zd MB page size is not supported\n",
                    (system.host_page_size/(1024*1024)));
            return 1;
        }
    }

    system.vm = ioctl(system.kvm, KVM_CREATE_VM, NULL);
    system.vcpu.fd = ioctl(system.vm, KVM_CREATE_VCPU, (void*)0, NULL);

    ioctl(system.vcpu.fd, KVM_RUN, NULL);

    msr_list0.nmsrs = 0;
    ioctl(system.kvm, KVM_GET_MSR_INDEX_LIST, &msr_list0, NULL);
    num_msr = msr_list0.nmsrs;

    msr_list = malloc(sizeof(__u32) * num_msr + 1);
    msr_list->nmsrs = num_msr;
    ioctl(system.kvm, KVM_GET_MSR_INDEX_LIST, msr_list, NULL);
    system.vcpu_region_size = ioctl(system.kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

    struct kvm_run * run = (struct kvm_run*)mmap(0,
                                                 system.vcpu_region_size,
                                                 PROT_READ|PROT_WRITE, MAP_PRIVATE,
                                                 system.vcpu.fd, 0);

    char *initial_page;
    __u64 entry;
    initial_page = alloc_page(&system, 2);

    {
        if (optind >= argc) {
            usage(argv[0]);
        }

        int fd = open(argv[optind], O_RDONLY);
        if (fd < 0) {
            perror(argv[optind]);
            return 1;
        }

        struct stat st;
        fstat(fd, &st);

        if (st.st_size == 0) {
            fprintf(stderr, "sizeof executable is too small.\n");
            return 1;
        }

        size_t page_size = sysconf(_SC_PAGE_SIZE);
        size_t map_size = ((st.st_size + (page_size-1))/page_size)*page_size;

        char *elf = mmap(0, map_size, PROT_READ, MAP_PRIVATE,
                         fd, 0);
        if (elf == MAP_FAILED) {
            perror(argv[optind]);
            return 1;
        }
        close(fd);

        if (elf[0] != 0x7f ||
            elf[1] != 'E' ||
            elf[2] != 'L' ||
            elf[3] != 'F')
        {
            fprintf(stderr, "executable is not ELF.\n");
            return 1;
        }

        Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
        char *phdr_ptr = elf + ehdr->e_phoff;
        entry = ehdr->e_entry;

        for (int pi=0; pi<ehdr->e_phnum; pi++) {
            Elf64_Phdr *phdr = (Elf64_Phdr*)phdr_ptr;

            if (phdr->p_flags & PT_LOAD) {
                load_segment(initial_page - (0x00200000), phdr, elf);
            }

            phdr_ptr += ehdr->e_phentsize;
        }

        munmap(elf, map_size);
    }

    setup_initial_page(&system, initial_page, system.host_page_size * 2);
    setup_vcpu(&system, &system.vcpu, entry);

    {
        ioctl(system.vcpu.fd, KVM_RUN, NULL);

        {
            struct kvm_translation tr = {0};
            tr.linear_address = 0x00400000;

            ioctl(system.vcpu.fd, KVM_TRANSLATE, &tr, NULL);

            printf("%llx\n", (long long)tr.physical_address);
        }

        dump_regs(&system.vcpu);

        switch (run->exit_reason) {
        case KVM_EXIT_INTERNAL_ERROR:
            printf("exit internal error : %d [", (int)run->internal.suberror);
            for (int ei=0; ei<run->internal.ndata; ei++) {
                printf("%llx, ", (long long)run->internal.data[ei]);
            }
            printf("]\n");
            break;

        case KVM_EXIT_MMIO:
            printf("reference unmapped region : addr=%16llx\n",
                   (long long)run->mmio.phys_addr);
            break;

        case KVM_EXIT_HLT:
            printf("vm halted\n");
            break;

        case KVM_EXIT_FAIL_ENTRY:
            printf("fail entry : reason=%llx\n",
                   (long long)run->fail_entry.hardware_entry_failure_reason);
            break;

        default:
            printf("unknown exit %d\n", run->exit_reason);
            break;
        }
    }

    return 0;
}