/*
 * firewallExtension.c
 *
 * A Linux kernel module that extends the firewall to restrict which programs
 * are allowed to make outgoing TCP connections on a given port.
 *
 * How it works:
 *   - Rules are stored as (port, program_path) pairs.
 *   - If no rules exist for a port, ALL programs may connect on that port.
 *   - If rules DO exist for a port, ONLY listed programs may connect.
 *   - Rules are configured from user space via /proc/firewallExtension.
 *   - Writing "LIST\n" to that file causes all rules to be printed to kern.log.
 *   - Writing rule lines ("port /full/path\n" ...) replaces the rule set atomically.
 *
 * Concurrency design:
 *   Many outgoing connections (packet handler calls) can happen simultaneously,
 *   so they use read_lock — multiple readers allowed at once.
 *   Rule updates use write_lock — exclusive, blocks all readers.
 *   This maximises parallelism as required by the spec.
 *   Reference: Linux Kernel Development, Ch.10 (Kernel Synchronisation Methods)
 *              https://www.kernel.org/doc/html/latest/kernel-hacking/locking.html
 *
 * Author: [your name]
 * Based on example code provided by Eike Ritter, University of Birmingham
 */

#include <linux/module.h>          /* Required for all kernel modules */
#include <linux/kernel.h>          /* For printk and KERN_INFO */
#include <linux/netfilter.h>       /* Netfilter hook infrastructure */
#include <linux/netfilter_ipv4.h>  /* NF_INET_LOCAL_OUT, priorities */
#include <linux/skbuff.h>          /* sk_buff — the packet buffer structure */
#include <net/tcp.h>               /* tcp_hdr(), tcp_done() */
#include <linux/namei.h>           /* kern_path(), LOOKUP_FOLLOW */
#include <linux/version.h>         /* LINUX_VERSION_CODE */
#include <linux/sched/mm.h>        /* get_task_mm(), mmput() */
#include <linux/proc_fs.h>         /* proc_create(), proc_remove() */
#include <linux/uaccess.h>         /* copy_from_user() */
#include <linux/slab.h>            /* kmalloc(), kfree() */
#include <linux/rwlock.h>          /* DEFINE_RWLOCK, read_lock, write_lock */
#include <linux/atomic.h>          /* atomic_t, atomic_cmpxchg */
#include <linux/dcache.h>          /* d_path() */
#include <linux/string.h>          /* strncpy, strncmp */

MODULE_AUTHOR("Eike Ritter <E.Ritter@cs.bham.ac.uk>");
MODULE_DESCRIPTION("Firewall extension: per-program port control");
MODULE_LICENSE("GPL");

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */
#define MAX_RULES       64          /* Maximum number of firewall rules */
#define MAX_PATH_LEN    256         /* Maximum length of an executable path */
#define MAX_WRITE_BUF   (MAX_RULES * (MAX_PATH_LEN + 16))  /* Max /proc write */
#define PROC_FILENAME   "firewallExtension"

/* -------------------------------------------------------------------------
 * Rule storage
 *
 * We use a fixed-size array of rules rather than a linked list for simplicity.
 * Two copies exist: the live set (rules/num_rules) and a scratch space used
 * during atomic replacement (new_rules/new_num_rules).
 * Protected by rules_lock (rwlock).
 * ------------------------------------------------------------------------- */
struct firewall_rule {
    int  port;                  /* TCP destination port this rule applies to */
    char program[MAX_PATH_LEN]; /* Full path of the permitted executable */
};

/* The active rule set — read by the hook, written only during updates */
static struct firewall_rule rules[MAX_RULES];
static int                  num_rules = 0;

/*
 * rwlock: allows many concurrent readers (packet handlers) but only one
 * writer (rule update). This maximises parallelism.
 * Reference: https://www.kernel.org/doc/html/latest/kernel-hacking/locking.html
 */
static DEFINE_RWLOCK(rules_lock);

/* Ensures only one process can have /proc/firewallExtension open at a time */
static atomic_t proc_in_use = ATOMIC_INIT(0);

/* The /proc entry — kept so we can remove it on unload */
static struct proc_dir_entry *proc_entry;

/* -------------------------------------------------------------------------
 * Helper: check if the currently-running process is allowed on 'port'
 *
 * Returns 1 (allowed) or 0 (blocked).
 * Called from inside the netfilter hook with read_lock already held.
 * ------------------------------------------------------------------------- */
static int is_allowed(int port)
{
    int i;
    int rules_exist_for_port = 0;
    struct path  exe_path;
    char        *exe_full_path;
    char         path_buf[MAX_PATH_LEN];
    char         proc_exe[64];  /* "/proc/<pid>/exe" */
    int          allowed = 0;

    /*
     * First pass: find out whether any rule mentions this port.
     * If none do, the connection is allowed unconditionally.
     */
    for (i = 0; i < num_rules; i++) {
        if (rules[i].port == port) {
            rules_exist_for_port = 1;
            break;
        }
    }

    if (!rules_exist_for_port)
        return 1; /* No restriction on this port */

    /*
     * Rules exist for this port. Resolve the executable path of the
     * current process via /proc/<pid>/exe, following the technique shown
     * in findExecutable.c (provided by E. Ritter).
     *
     * kern_path resolves the symlink /proc/<pid>/exe to the actual file.
     * d_path then gives us the full absolute path as a string.
     * Reference: findExecutable.c (Eike Ritter, UoB); linux/namei.h
     */
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", current->pid);

    if (kern_path(proc_exe, LOOKUP_FOLLOW, &exe_path) != 0) {
        printk(KERN_INFO "firewall: Could not resolve exe path for pid %d\n",
               current->pid);
        return 0; /* Fail closed: deny if we cannot identify the program */
    }

    exe_full_path = d_path(&exe_path, path_buf, MAX_PATH_LEN);
    path_put(&exe_path); /* Release reference — always required after kern_path */

    if (IS_ERR(exe_full_path)) {
        printk(KERN_INFO "firewall: d_path failed for pid %d\n", current->pid);
        return 0; /* Fail closed */
    }

    /* Second pass: check if this executable appears in the allowed list */
    for (i = 0; i < num_rules; i++) {
        if (rules[i].port == port &&
            strncmp(exe_full_path, rules[i].program, MAX_PATH_LEN) == 0) {
            allowed = 1;
            break;
        }
    }

    return allowed;
}

/* -------------------------------------------------------------------------
 * Netfilter hook — called for every outgoing packet
 *
 * Based on the skeleton provided by Eike Ritter (firewallExtension.c).
 * We only act on TCP SYN packets (initial connection requests).
 * ------------------------------------------------------------------------- */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
#endif

static unsigned int FirewallExtensionHook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct tcphdr   *tcp;
    struct iphdr    *ip;
    struct ipv6hdr  *ip6;
    struct sock     *sk;
    struct mm_struct *mm;
    int port;

    sk = skb->sk;
    if (!sk) {
        printk(KERN_INFO "firewall: packet with no socket, accepting\n");
        return NF_ACCEPT;
    }

    /* Handle IPv6 — check it's TCP, then fall through to port check */
    if (sk->sk_family == AF_INET6) {
        ip6 = ipv6_hdr(skb);
        if (!ip6) {
            printk(KERN_INFO "firewall: no IPv6 header, accepting\n");
            return NF_ACCEPT;
        }
        if (ip6->nexthdr != IPPROTO_TCP)
            return NF_ACCEPT; /* Not TCP — not our concern */
    }
    /* Handle IPv4 */
    else if (sk->sk_family == AF_INET) {
        ip = ip_hdr(skb);
        if (!ip) {
            printk(KERN_INFO "firewall: no IP header, accepting\n");
            return NF_ACCEPT;
        }
        if (ip->protocol != IPPROTO_TCP)
            return NF_ACCEPT; /* Not TCP — not our concern */
    }
    else {
        return NF_ACCEPT; /* Not IPv4 or IPv6 — ignore */
    }

    /* Get the TCP header */
    tcp = tcp_hdr(skb);
    if (!tcp) {
        printk(KERN_INFO "firewall: no TCP header, accepting\n");
        return NF_ACCEPT;
    }

    /*
     * Only check SYN packets — these are the start of a new connection.
     * Checking every packet would be far too expensive.
     * Once a SYN is allowed through, the rest of the connection follows.
     */
    if (!tcp->syn)
        return NF_ACCEPT;

    /*
     * We need to be in user process context to resolve the executable.
     * The get_task_mm check (from the provided skeleton) confirms this.
     * If we're in interrupt context, we can't safely call kern_path.
     */
    if (in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
        printk(KERN_INFO "firewall: not in user context, accepting packet\n");
        return NF_ACCEPT;
    }
    mmput(mm); /* We only needed this for the context check — release it */

    port = ntohs(tcp->dest);
    printk(KERN_INFO "firewall: SYN on port %d from pid %d\n",
           port, current->pid);

    /*
     * Check the rule set under read_lock.
     * read_lock allows multiple packet handlers to run concurrently —
     * they only block each other when a rule update (write_lock) is in progress.
     */
    read_lock(&rules_lock);
    if (!is_allowed(port)) {
        read_unlock(&rules_lock);
        printk(KERN_INFO "firewall: BLOCKING connection on port %d\n", port);
        tcp_done(sk); /* Terminate the TCP connection immediately */
        return NF_DROP;
    }
    read_unlock(&rules_lock);

    printk(KERN_INFO "firewall: ALLOWING connection on port %d\n", port);
    return NF_ACCEPT;
}

/* -------------------------------------------------------------------------
 * /proc file operations
 * ------------------------------------------------------------------------- */

/*
 * proc_open — called when a process opens /proc/firewallExtension.
 * We use an atomic compare-and-swap to ensure only one process can
 * have the file open at any time. Returns -EAGAIN if already open.
 * Reference: https://www.kernel.org/doc/html/latest/driver-api/basics.html
 */
static int fw_proc_open(struct inode *inode, struct file *file)
{
    /*
     * atomic_cmpxchg(ptr, old, new):
     *   If *ptr == old, set *ptr = new and return old.
     *   If *ptr != old, return current value (not old).
     * So if the return value is not 0, the file was already open.
     */
    if (atomic_cmpxchg(&proc_in_use, 0, 1) != 0) {
        printk(KERN_INFO "firewall: /proc file already open, returning EAGAIN\n");
        return -EAGAIN;
    }
    return 0;
}

/*
 * fw_proc_release — called when the process closes /proc/firewallExtension.
 * Clears the in-use flag so another process can open it.
 */
static int fw_proc_release(struct inode *inode, struct file *file)
{
    atomic_set(&proc_in_use, 0);
    return 0;
}

/*
 * fw_proc_write — called when user space writes to /proc/firewallExtension.
 *
 * Two protocols:
 *   "LIST\n"           → print current rules to kern.log via printk
 *   "<port> <path>\n"  → (one or more lines) replace the full rule set
 *
 * Atomic replacement: we parse into a temporary array first. Only if ALL
 * lines are valid do we swap it in under write_lock. On any parse error,
 * the old rules are completely untouched.
 */
static ssize_t fw_proc_write(struct file *file, const char __user *ubuf,
                             size_t count, loff_t *ppos)
{
    char *kbuf;
    char *line;
    char *cursor;
    char *line_end;

    /* Temporary rule set built during parsing — only swapped in on success */
    struct firewall_rule *new_rules;
    int new_num = 0;
    new_rules = kmalloc(MAX_RULES * sizeof(struct firewall_rule), GFP_KERNEL);
    if (!new_rules) {
        return -ENOMEM;
    }

    int port;
    char prog[MAX_PATH_LEN];
    int parse_ok = 1;
    int i;

    /* Sanity-check the write size */
    if (count == 0 || count > MAX_WRITE_BUF) {
        printk(KERN_INFO "firewall: proc write size %zu out of range\n", count);
        kfree(new_rules);
        return -EINVAL;
    }

    /* Allocate a kernel buffer and copy from user space */
    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf){
        kfree(new_rules);
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, ubuf, count)) {
        return -EFAULT;
    }
    kbuf[count] = '\0'; /* Null-terminate so we can use string functions */

    /* --- Handle the LIST command --- */
    if (strcmp(kbuf, "LIST\n") == 0 || strcmp(kbuf, "LIST") == 0) {
        printk(KERN_INFO "firewall: listing rules\n");
        read_lock(&rules_lock);
        for (i = 0; i < num_rules; i++) {
            printk(KERN_INFO "Firewall rule: %d %s\n",
                   rules[i].port, rules[i].program);
        }
        if (num_rules == 0)
            printk(KERN_INFO "firewall: no rules configured\n");
        read_unlock(&rules_lock);
        kfree(kbuf);
        kfree(new_rules);
        return count;
    }

    /* --- Parse new rule set line by line --- */
    cursor = kbuf;

    while (*cursor != '\0' && parse_ok) {
        /* Find the end of this line */
        line = cursor;
        line_end = strchr(cursor, '\n');

        if (line_end != NULL) {
            *line_end = '\0';      /* Temporarily terminate the line */
            cursor = line_end + 1; /* Advance to next line */
        } else {
            cursor = cursor + strlen(cursor); /* Last line, no newline */
        }

        /* Skip blank lines */
        if (strlen(line) == 0)
            continue;

        /* Each line must be "port /full/path" */
        if (sscanf(line, "%d %255s", &port, prog) != 2) {
            printk(KERN_INFO "firewall: malformed rule line: '%s'\n", line);
            parse_ok = 0;
            break;
        }

        /* Port must be in valid TCP range */
        if (port < 1 || port > 65535) {
            printk(KERN_INFO "firewall: port %d out of range\n", port);
            parse_ok = 0;
            break;
        }

        /* Don't overflow our temporary array */
        if (new_num >= MAX_RULES) {
            printk(KERN_INFO "firewall: too many rules (max %d)\n", MAX_RULES);
            parse_ok = 0;
            break;
        }

        new_rules[new_num].port = port;
        strncpy(new_rules[new_num].program, prog, MAX_PATH_LEN - 1);
        new_rules[new_num].program[MAX_PATH_LEN - 1] = '\0';
        new_num++;
    }

    /*
     * Atomic replacement:
     * Only if every line parsed successfully do we take the write_lock and
     * swap in the new rules. If anything failed, we return -EINVAL and the
     * original rules remain untouched.
     */
    if (parse_ok) {
        write_lock(&rules_lock);
        memcpy(rules, new_rules, new_num * sizeof(struct firewall_rule));
        num_rules = new_num;
        write_unlock(&rules_lock);
        printk(KERN_INFO "firewall: %d rule(s) loaded successfully\n", new_num);
    } else {
        printk(KERN_INFO "firewall: parse error — old rules retained\n");
        kfree(kbuf);
        kfree(new_rules);
        return -EINVAL;
    }

    kfree(kbuf);
    kfree(new_rules);
    return count;
}

/* proc_ops for kernel 5.6+ (our kernel is 6.6, so this is correct)
 * Reference: https://www.kernel.org/doc/html/latest/filesystems/proc.html */
static const struct proc_ops fw_proc_ops = {
    .proc_open    = fw_proc_open,
    .proc_write   = fw_proc_write,
    .proc_release = fw_proc_release,
};

/* Netfilter hook registration structure (from provided skeleton) */
static struct nf_hook_ops firewallExtension_ops = {
    .hook     = FirewallExtensionHook,
    .pf       = NFPROTO_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum  = NF_INET_LOCAL_OUT,
};

/* -------------------------------------------------------------------------
 * Module init and exit
 * ------------------------------------------------------------------------- */

int init_module(void)
{
    int err;

    /* Create /proc/firewallExtension with rw permissions for root */
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &fw_proc_ops);
    if (!proc_entry) {
        printk(KERN_INFO "firewall: failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }

    /* Register the netfilter hook for outgoing packets */
    err = nf_register_net_hook(&init_net, &firewallExtension_ops);
    if (err) {
        printk(KERN_INFO "firewall: failed to register netfilter hook\n");
        proc_remove(proc_entry);
        return err;
    }

    printk(KERN_INFO "firewall: module loaded, /proc/%s created\n",
           PROC_FILENAME);
    return 0;
}

void cleanup_module(void)
{
    /* Unregister the hook first so no new packets are processed */
    nf_unregister_net_hook(&init_net, &firewallExtension_ops);

    /* Remove the /proc entry */
    proc_remove(proc_entry);

    printk(KERN_INFO "firewall: module unloaded, all extensions removed\n");
}
