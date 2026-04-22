/*
 * A Linux kernel module that extends the firewall to restrict which programs
 * are allowed to make outgoing TCP connections on a given port.
 *
 * How it works:
 *   - Rules are stored as (port, program_path) pairs.
 *   - If no rules exist for a port, ALL programs may connect on that port.
 *   - If rules exist for a port, only listed programs may connect.
 *   - Rules are configured from user space via /proc/firewallExtension.
 */

#include <linux/module.h>          
#include <linux/kernel.h>          
#include <linux/netfilter.h>       
#include <linux/netfilter_ipv4.h>  
#include <linux/skbuff.h>          
#include <net/tcp.h>               
#include <linux/namei.h>           
#include <linux/version.h>         
#include <linux/sched/mm.h>        
#include <linux/proc_fs.h>         
#include <linux/uaccess.h>         
#include <linux/slab.h>            
#include <linux/rwlock.h>          
#include <linux/atomic.h>          
#include <linux/dcache.h>         
#include <linux/string.h>          

// Constants for rule storage and /proc buffer sizes

#define MAX_RULES       64          
#define MAX_PATH_LEN    256         
#define MAX_WRITE_BUF   (MAX_RULES * (MAX_PATH_LEN + 16))  
#define PROC_FILENAME   "firewallExtension"

// Module metadata

MODULE_AUTHOR("Ryan Hooper");
MODULE_DESCRIPTION("Firewall extension: per-program port control");
MODULE_LICENSE("GPL");

//Rule storage
struct firewall_rule {
    int  port;                  
    char program[MAX_PATH_LEN]; 
};

// Module metadata

static struct firewall_rule rules[MAX_RULES];
static int                  num_rules = 0;

// Synchronization for rule access

static DEFINE_RWLOCK(rules_lock);

static atomic_t proc_in_use = ATOMIC_INIT(0);

static struct proc_dir_entry *proc_entry;

//Helper function

static int is_allowed(int port)
{
    
    int i;
    int rules_exist_for_port = 0;
    struct path  exe_path;
    char        *exe_full_path;
    char         path_buf[MAX_PATH_LEN];
    char         proc_exe[64];  
    int          allowed = 0;

   
    for (i = 0; i < num_rules; i++) {
        if (rules[i].port == port) {
            rules_exist_for_port = 1;
            break;
        }
    }

    if (!rules_exist_for_port)
        return 1; 
     
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", current->pid);
    if (kern_path(proc_exe, LOOKUP_FOLLOW, &exe_path) != 0) {
        printk(KERN_INFO "firewall: Could not resolve exe path for pid %d\n",
               current->pid);
        return 0; 
    }
    
    exe_full_path = d_path(&exe_path, path_buf, MAX_PATH_LEN);
    path_put(&exe_path); 
    
    if (IS_ERR(exe_full_path)) {
        printk(KERN_INFO "firewall: d_path failed for pid %d\n", current->pid);
        return 0; 
    }
    
    for (i = 0; i < num_rules; i++) {
        if (rules[i].port == port &&
            strncmp(exe_full_path, rules[i].program, MAX_PATH_LEN) == 0) {
            allowed = 1;
            break;
        }
    }

    return allowed;
}

// Netfilter hook function and /proc file operations

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
#endif

static unsigned int FirewallExtensionHook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
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
    // Check if it's IPv4 or IPv6 and if it's TCP. If not TCP, accept the packet.
    if (sk->sk_family == AF_INET6) {
        ip6 = ipv6_hdr(skb);
        if (!ip6) {
            printk(KERN_INFO "firewall: no IPv6 header, accepting\n");
            return NF_ACCEPT;
        }
        if (ip6->nexthdr != IPPROTO_TCP)
            return NF_ACCEPT; 
    }
    else if (sk->sk_family == AF_INET) {
        ip = ip_hdr(skb);
        if (!ip) {
            printk(KERN_INFO "firewall: no IP header, accepting\n");
            return NF_ACCEPT;
        }
        if (ip->protocol != IPPROTO_TCP)
            return NF_ACCEPT; 
    }
    else {
        return NF_ACCEPT; 
    }
    
    tcp = tcp_hdr(skb);
    if (!tcp) {
        printk(KERN_INFO "firewall: no TCP header, accepting\n");
        return NF_ACCEPT;
    }


    if (!tcp->syn)
        return NF_ACCEPT;

    
    if (in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
        printk(KERN_INFO "firewall: not in user context, accepting packet\n");
        return NF_ACCEPT;
    }
    mmput(mm); 
    // Get the destination port in host byte order
    port = ntohs(tcp->dest);
    printk(KERN_INFO "firewall: SYN on port %d from pid %d\n",
           port, current->pid);
    // Check if this port is allowed for the current process
    read_lock(&rules_lock);
    if (!is_allowed(port)) {
        // Port is blocked for this process. Drop the packet.
        read_unlock(&rules_lock);
        printk(KERN_INFO "firewall: BLOCKING connection on port %d\n", port);
        tcp_done(sk); 
        return NF_DROP;
    }
    read_unlock(&rules_lock);
    printk(KERN_INFO "firewall: ALLOWING connection on port %d\n", port);
    return NF_ACCEPT;
}

//proc_ops for /proc/firewallExtension 

//Open
static int fw_proc_open(struct inode *inode, struct file *file)
{
    
    if (atomic_cmpxchg(&proc_in_use, 0, 1) != 0) {
        printk(KERN_INFO "firewall: /proc file already open, returning EAGAIN\n");
        return -EAGAIN;
    }
    return 0;
}
// Release
static int fw_proc_release(struct inode *inode, struct file *file)
{
    atomic_set(&proc_in_use, 0);
    return 0;
}
//  Write: handle LIST and W commands from user space
static ssize_t fw_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    char *kbuf;
    char *line;
    char *cursor;
    char *line_end;

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

    if (count == 0 || count > MAX_WRITE_BUF) {
        printk(KERN_INFO "firewall: proc write size %zu out of range\n", count);
        kfree(new_rules);
        return -EINVAL;
    }
    // Copy the user buffer into kernel space and null-terminate it
    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf){
        kfree(new_rules);
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, ubuf, count)) {
        return -EFAULT;
    }
    kbuf[count] = '\0'; 

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

    // Parse the buffer line by line, validating each rule
    cursor = kbuf;

    while (*cursor != '\0' && parse_ok) {
        line = cursor;
        line_end = strchr(cursor, '\n');

        if (line_end != NULL) {
            *line_end = '\0';      
            cursor = line_end + 1;
        } else {
            cursor = cursor + strlen(cursor); 
        }

        if (strlen(line) == 0)
            continue;

        if (sscanf(line, "%d %255s", &port, prog) != 2) {
            printk(KERN_INFO "firewall: malformed rule line: '%s'\n", line);
            parse_ok = 0;
            break;
        }

        if (port < 1 || port > 65535) {
            printk(KERN_INFO "firewall: port %d out of range\n", port);
            parse_ok = 0;
            break;
        }

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
    // If all rules are valid, replace the old rules atomically. Otherwise, discard the new rules and keep the old ones.
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
static const struct proc_ops fw_proc_ops = {
    .proc_open    = fw_proc_open,
    .proc_write   = fw_proc_write,
    .proc_release = fw_proc_release,
};

static struct nf_hook_ops firewallExtension_ops = {
    .hook     = FirewallExtensionHook,
    .pf       = NFPROTO_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum  = NF_INET_LOCAL_OUT,
};

// Module initialization and cleanup

int init_module(void)
{
    int err;
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &fw_proc_ops);
    if (!proc_entry) {
        printk(KERN_INFO "firewall: failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }

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
    nf_unregister_net_hook(&init_net, &firewallExtension_ops);

    proc_remove(proc_entry);

    printk(KERN_INFO "firewall: module unloaded, all extensions removed\n");
}
