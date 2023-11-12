#include <asm/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/slab.h>
#include <linux/time_namespace.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/mm.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("LeshaInc");
MODULE_DESCRIPTION("OS lab 2");

struct task_info {
    pid_t tid;
    char state;
    char command[16];
    u64 utime_ns;
    u64 stime_ns;
    u64 start_time_ns;
    u64 min_flt;
    u64 maj_flt;
    s32 prio;
    s32 nice;
    u32 cpu;
};

struct process_info {
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    pid_t sid;
    u64 vss;
    u64 rss;
    size_t num_tasks;
    struct task_info tasks[];
};

static struct process_info *collect_process_info(struct pid *pid) {
    struct task_struct *task;
    struct process_info *pinfo;
    struct task_info *tinfo;
    struct mm_struct *mm;
    size_t num_tasks;

    do_each_pid_thread(pid, PIDTYPE_PID, task) {
        num_tasks++;
    } while_each_pid_thread(pid, PIDTYPE_PID, task);

    if (num_tasks == 0)
        return NULL;

    pinfo = kmalloc(sizeof(struct process_info) + sizeof(struct task_info) * num_tasks, GFP_KERNEL);
    if (pinfo == NULL)
        return NULL;

    task = get_pid_task(pid, PIDTYPE_PID);
    
    pinfo->pid = pid_vnr(pid);
    pinfo->sid = task_session_vnr(task);
		pinfo->ppid = task_tgid_vnr(task->real_parent);
		pinfo->pgid = task_pgrp_vnr(task);
    pinfo->num_tasks = num_tasks;

    pinfo->vss = 0;
    pinfo->rss = 0;
    mm = get_task_mm(task);
    if (mm) {
        pinfo->vss = PAGE_SIZE * mm->total_vm;
        pinfo->rss = PAGE_SIZE * get_mm_rss(mm);
    }

    tinfo = pinfo->tasks;
    do_each_pid_thread(pid, PIDTYPE_PID, task) {
        tinfo->tid = task_pid_vnr(task);
        tinfo->state = task_state_index(task);
        get_task_comm(tinfo->command, task);
        task_cputime_adjusted(task, &tinfo->utime_ns, &tinfo->stime_ns);
        tinfo->start_time_ns = timens_add_boottime_ns(task->start_boottime);
        tinfo->min_flt = task->min_flt;
        tinfo->maj_flt = task->maj_flt;
        tinfo->prio = task->prio - MAX_RT_PRIO;
        tinfo->nice = task_nice(task);
        tinfo->cpu = task_cpu(task);
        tinfo++;
    } while_each_pid_thread(pid, PIDTYPE_PID, task);

    return pinfo;
}

#define IOCTL_MAGIC 'a'
#define WR_PID _IOW(IOCTL_MAGIC, 1, pid_t)
#define RD_NUM_TASKS _IOR(IOCTL_MAGIC, 2, size_t)
#define RD_PINFO _IOR(IOCTL_MAGIC, 3, struct process_info)

static dev_t pidstat_dev = 0;
static struct process_info *pidstat_pinfo = NULL;
static atomic_t pidstat_busy;
static struct class *pidstat_dev_class;
static struct cdev pidstat_cdev;

static void free_pidstat_pinfo(void) {
    if (pidstat_pinfo != NULL) {
        kfree(pidstat_pinfo);
        pidstat_pinfo = NULL;
    }
}

static int      pidstat_open(struct inode *inode, struct file *file);
static int      pidstat_release(struct inode *inode, struct file *file);
static ssize_t  pidstat_read(struct file *filp, char __user *buf, size_t len, loff_t * off);
static ssize_t  pidstat_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long     pidstat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .read           = pidstat_read,
    .write          = pidstat_write,
    .open           = pidstat_open,
    .unlocked_ioctl = pidstat_ioctl,
    .release        = pidstat_release,
};

static int pidstat_open(struct inode *inode, struct file *file) {
    if (atomic_cmpxchg(&pidstat_busy, 0, 1) == 1) {
        return -EBUSY;
    }

    free_pidstat_pinfo();
    return 0;
}

static int pidstat_release(struct inode *inode, struct file *file) {
    atomic_set(&pidstat_busy, 0);
    free_pidstat_pinfo();
    return 0;
}

static ssize_t pidstat_read(struct file *filp, char __user *buf, size_t len, loff_t * off) {
    return 0;
}

static ssize_t pidstat_write(struct file *filp, const char *buf, size_t len, loff_t * off) {
    return 0;
}

static long pidstat_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch(cmd) {

    case WR_PID:
        pid_t pid_num;
        if (copy_from_user(&pid_num, (pid_t*) arg, sizeof(pid_t))) {
            return -EINVAL;
        }

        rcu_read_lock();
        
        struct pid *pid = find_vpid(pid_num);
        if (pid == NULL) {
            rcu_read_unlock();
            return -ENOENT;
        }

        pidstat_pinfo = collect_process_info(pid);
        rcu_read_unlock();

        return 0;

    case RD_NUM_TASKS:
        if (pidstat_pinfo == NULL) {
            return -ENOENT;
        }

        if (copy_to_user((size_t*) arg, &pidstat_pinfo->num_tasks, sizeof(size_t))) {
            return -EINVAL;
        }

        return 0;

    case RD_PINFO:
        if (pidstat_pinfo == NULL) {
            return -ENOENT;
        }

        size_t size = sizeof(struct process_info) + sizeof(struct task_info) * pidstat_pinfo->num_tasks;
        if (copy_to_user((struct process_info*) arg, pidstat_pinfo, size)) {
            return -EINVAL;
        }

        free_pidstat_pinfo();
        return 0;

    default:
        return -EINVAL;

    }
}

static int __init pidstat_init(void) {
    pr_info("hello");

    if ((alloc_chrdev_region(&pidstat_dev, 0, 1, "pidstat")) < 0) {
        pr_err("alloc_chrdev_region failed\n");
        return -1;
    }

    cdev_init(&pidstat_cdev, &fops);

    if ((cdev_add(&pidstat_cdev, pidstat_dev, 1)) < 0) {
        pr_err("cdev_add failed\n");
        class_destroy(pidstat_dev_class);
        return -1;
    }

    if (IS_ERR(pidstat_dev_class = class_create("pidstat_class"))) {
        pr_err("class_create failed\n");
        class_destroy(pidstat_dev_class);
        return -1;
    }

    if(IS_ERR(device_create(pidstat_dev_class, NULL, pidstat_dev, NULL, "pidstat"))){
        pr_err("device_create failed\n");
        class_destroy(pidstat_dev_class);
        unregister_chrdev_region(pidstat_dev, 1);
        return -1;
    }

    atomic_set(&pidstat_busy, 0);

    return 0;
}

static void __exit pidstat_cleanup(void) {
    device_destroy(pidstat_dev_class, pidstat_dev);
    class_destroy(pidstat_dev_class);
    cdev_del(&pidstat_cdev);
    unregister_chrdev_region(pidstat_dev, 1);
    free_pidstat_pinfo();
    pr_info("goodbye");
}

module_init(pidstat_init);
module_exit(pidstat_cleanup);
