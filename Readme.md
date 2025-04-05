# IAN - Project 2

### Author: Adam Veselý
### Login: xvesela00
### Time spent: ~14 hours (with breaks)
### Github page for easier viewing: https://github.com/H0CK3Y03/IAN---Kernel-Vmcore-Analysis
---
# 1. Using crash to find the root cause of the panic

## Initial output when running `crash`:
      KERNEL: vmlinux-5.14.0-503.15.1.el9_5.x86_64  [TAINTED]
    DUMPFILE: vmcore  [PARTIAL DUMP]
        CPUS: 4
        DATE: Sun Dec  8 16:27:44 CET 2024
      UPTIME: 00:08:12
    LOAD AVERAGE: 2.64, 1.20, 0.46
       TASKS: 213
    NODENAME: localhost.localdomain
     RELEASE: 5.14.0-503.15.1.el9_5.x86_64
     VERSION: #1 SMP PREEMPT_DYNAMIC Thu Nov 14 15:45:31 EST 2024
     MACHINE: x86_64  (2496 Mhz)
      MEMORY: 8 GB
       PANIC: "Kernel panic - not syncing: hung_task: blocked tasks"
         PID: 47
     COMMAND: "khungtaskd"
        TASK: ffff9a2232e30000  [THREAD_INFO: ffff9a2232e30000]
         CPU: 1
       STATE: TASK_RUNNING (PANIC)

- We can see that the kernel has been tainted: `KERNEL: vmlinux-5.14.0-503.15.1.el9_5.x86_64  [TAINTED]`, which means a non-standard kernel module has been loaded.
- The system has 4 CPUs: `CPUS: 4`
- The system had been running for 8 minutes and 12 seconds before the crash: `UPTIME: 00:08:12`.
- The system was running 213 tasks at the time of the crash: `TASKS: 213`.
- The kernel panic message: `PANIC: "Kernel panic - not syncing: hung_task: blocked tasks"` indicates, that the kernel encountered a **hung task** scenario, where the task `ffff9a2232e30000` and command `khungtaskd` whose `PID` is `47` detected that a process has been running for too long without making progress, indicating a deadlock or infinite loop:
`PID: 47`,
`COMMAND: "khungtaskd"`
`TASK: ffff9a2232e30000  [THREAD_INFO: ffff9a2232e30000]`
- The panic call occurred on CPU 1: `CPU: 1`.
- We can see that the process state is running, therefore we should see it on CPU1's runqueue: `STATE: TASK_RUNNING (PANIC)`.
---
## `log`
    [  277.000573] smajdalf: loading out-of-tree module taints kernel.
    [  277.000584] smajdalf: module license 'RH-EDU' taints kernel.
    [  277.000588] Disabling lock debugging due to kernel taint
    [  277.000590] smajdalf: module verification failed: signature and/or required key  missing - tainting kernel
    [  277.000592] smajdalf: module license taints kernel.
    [  277.001905] Smajdalf: Carodej nikdy nechodi pozde.
    [  492.326391] INFO: task systemd:1 blocked for more than 122 seconds.
    [  492.326437]       Tainted: P           OE     -------  ---  5.14.0-503.15.1.el9_5.   x86_64 #1
    [  492.326462] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this     message.
    [  492.326484] task:systemd         state:D stack:0     pid:1     tgid:1        ppid:0      flags:0x00000002
    [  492.326516] Call Trace:
    [  492.326527]  <TASK>
    [  492.326540]  __schedule+0x229/0x550
    [  492.326566]  schedule+0x2e/0xd0
    [  492.326581]  schedule_preempt_disabled+0x11/0x20
    [  492.326601]  rwsem_down_read_slowpath+0x37f/0x4f0
    [  492.326620]  ? syscall_enter_from_user_mode+0x40/0x80
    [  492.326643]  down_read+0x45/0xa0
    [  492.326657]  do_user_addr_fault+0x415/0x6a0
    [  492.326676]  ? syscall_exit_to_user_mode+0x19/0x40
    [  492.326697]  exc_page_fault+0x62/0x150
    [  492.326717]  asm_exc_page_fault+0x22/0x30
    [  492.326735] RIP: 0033:0x7f1601861cfc
    [  492.326781] RSP: 002b:00007ffdb255fb80 EFLAGS: 00010246
    [  492.326801] RAX: 0000000000000001 RBX: 0000000000000000 RCX: 000000000003f282
    [  492.326823] RDX: 000056172528ac80 RSI: 7fffffffffffffff RDI: 431bde82d7b634db
    [  492.326844] RBP: 0000561724f67dc0 R08: 0000000000000006 R09: 00000059d60a512d
    [  492.326865] R10: 00007ffdb256b080 R11: 00007ffdb256b0f0 R12: 0000000000000000
    [  492.326886] R13: 0000000000000001 R14: 000056172517e240 R15: 0000561724f67c30
    [  492.326910]  </TASK>
    [  492.326967] Kernel panic - not syncing: hung_task: blocked tasks
    [  492.326987] CPU: 1 PID: 47 Comm: khungtaskd Kdump: loaded Tainted: P             OE     -------  ---  5.14.0-503.15.1.el9_5.x86_64 #1
    [  492.327022] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-1.   fc39 04/01/2014
    [  492.327081] Call Trace:
    [  492.327097]  <TASK>
    [  492.327107]  dump_stack_lvl+0x34/0x48
    [  492.327125]  panic+0x107/0x2bb
    [  492.327151]  check_hung_uninterruptible_tasks.cold+0xc/0xc
    [  492.327180]  ? __pfx_watchdog+0x10/0x10
    [  492.327199]  watchdog+0x9a/0xa0
    [  492.327215]  kthread+0xdd/0x100
    [  492.327240]  ? __pfx_kthread+0x10/0x10
    [  492.327260]  ret_from_fork+0x29/0x50
    [  492.327280]  </TASK>

- Includes the most interesting details, not the entire output.
- We can deduce that the kernel is tainted because of the module `smajdalf`: 
`[  277.000573] smajdalf: loading out-of-tree module taints kernel.`,
`[  277.000584] smajdalf: module license 'RH-EDU' taints kernel.`,
`[  277.000590] smajdalf: module verification failed: signature and/or required key  missing - tainting kernel`.
    To confirm this is the only module that is tainting the kernel we can check the log: `log | grep taint`, which confirms our suspicions:
```log | grep taint
[  277.000573] smajdalf: loading out-of-tree module taints kernel.
[  277.000584] smajdalf: module license 'RH-EDU' taints kernel.
[  277.000588] Disabling lock debugging due to kernel taint
[  277.000590] smajdalf: module verification failed: signature and/or required key missing - tainting kernel
```
- The log shows us that the `systemd` process with the `PID` of `1`: 
`[  492.326484] task:systemd         state:D stack:0     pid:1     tgid:1` 
has been blocked for more than 122 seconds: 
`[  492.326391] INFO: task systemd:1 blocked for more than 122 seconds.`.
Indicating that this is a **hung task** where a process like `systemd` is waiting in uninterruptible sleep for something and cannot continue (default is 120 seconds, so it checks out).
- The call trace associated with the `systemd` process shows that it is stuck in a read lock (probably a `rwsem_down_read_slowpath` issue): 
`[  492.326601]  rwsem_down_read_slowpath+0x37f/0x4f0`,
which indicates that the process is waiting to acquire a read lock, but it is being blocked.
- Examining the second calltrace we can see the condition when `panic` will be called: 
`[  492.327151]  check_hung_uninterruptible_tasks.cold+0xc/0xc`,
this function checks for hung tasks and triggers the panic if one is found.
- Ani moc brzo, The Lord of the Rings reference (or Šmajdalf) is nice :):
`[  277.001905] Smajdalf: Carodej nikdy nechodi pozde.`.
---
## `bt` - backtrace
    PID: 47     TASK: ffff9a2232e30000  CPU: 1   COMMAND: "khungtaskd"
    #0 [ffffbb29001a7d18] machine_kexec at ffffffff96e7a897
    #1 [ffffbb29001a7d70] __crash_kexec at ffffffff96ffaeaa
    #2 [ffffbb29001a7e30] panic at ffffffff97a74ce7
    #3 [ffffbb29001a7f00] watchdog at ffffffff9703d96a
    #4 [ffffbb29001a7f18] kthread at ffffffff96f38abd
    #5 [ffffbb29001a7f50] ret_from_fork at ffffffff96e03e89

- We can see that `panic` gets called after watchdog gets called (the order is from bottom to top, acting like a stack, where the oldest function gets inserted into the stack first, the rest get inserted on top of it), implying that between these 2 function calls a condition was met to call panic:
`#2 [ffffbb29001a7e30] panic at ffffffff97a74ce7`,
`#3 [ffffbb29001a7f00] watchdog at ffffffff9703d96a`.
---
# `dis watchdog` - disassemble watchdog
    0xffffffff9703d8d0 <watchdog>:  nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffff9703d8d5 <watchdog+5>:        push   %rbp
    0xffffffff9703d8d6 <watchdog+6>:        xor    %esi,%esi
    0xffffffff9703d8d8 <watchdog+8>:        movabs $0x7fffffffffffffff,%rbp
    0xffffffff9703d8e2 <watchdog+18>:       push   %rbx
    0xffffffff9703d8e3 <watchdog+19>:       mov    0x1bca0d6(%rip),%rbx        #    0xffffffff98c079c0 <jiffies>
    0xffffffff9703d8ea <watchdog+26>:       mov    %gs:0x32a00,%rdi
    0xffffffff9703d8f3 <watchdog+35>:       call   0xffffffff96f505b0 <set_user_nice>
    0xffffffff9703d8f8 <watchdog+40>:       mov    0x21431b1(%rip),%rdi        #    0xffffffff99180ab0 <sysctl_hung_task_timeout_secs>
    0xffffffff9703d8ff <watchdog+47>:       mov    0x21431a2(%rip),%rdx        #    0xffffffff99180aa8 <sysctl_hung_task_check_interval_secs>
    0xffffffff9703d906 <watchdog+54>:       cmp    %rdx,%rdi
    0xffffffff9703d909 <watchdog+57>:       mov    %rdx,%rax
    0xffffffff9703d90c <watchdog+60>:       cmovbe %rdi,%rax
    0xffffffff9703d910 <watchdog+64>:       test   %rdx,%rdx
    0xffffffff9703d913 <watchdog+67>:       cmove  %rdi,%rax
    0xffffffff9703d917 <watchdog+71>:       test   %rax,%rax
    0xffffffff9703d91a <watchdog+74>:       je     0xffffffff9703d942 <watchdog+114>
    0xffffffff9703d91c <watchdog+76>:       imul   $0x3e8,%rax,%rax
    0xffffffff9703d923 <watchdog+83>:       mov    0x1bca096(%rip),%rdx        #    0xffffffff98c079c0 <jiffies>
    0xffffffff9703d92a <watchdog+90>:       mov    %rbx,%r8
    0xffffffff9703d92d <watchdog+93>:       sub    %rdx,%r8
    0xffffffff9703d930 <watchdog+96>:       add    %rax,%r8
    0xffffffff9703d933 <watchdog+99>:       test   %r8,%r8
    0xffffffff9703d936 <watchdog+102>:      jle    0xffffffff9703d947 <watchdog+119>
    0xffffffff9703d938 <watchdog+104>:      mov    %r8,%rdi
    0xffffffff9703d93b <watchdog+107>:      call   0xffffffff97ae3350   <schedule_timeout_interruptible>
    0xffffffff9703d940 <watchdog+112>:      jmp    0xffffffff9703d8f8 <watchdog+40>
    0xffffffff9703d942 <watchdog+114>:      mov    %rbp,%r8
    0xffffffff9703d945 <watchdog+117>:      jmp    0xffffffff9703d938 <watchdog+104>
    0xffffffff9703d947 <watchdog+119>:      xor    %eax,%eax
    0xffffffff9703d949 <watchdog+121>:      xchg   %eax,0x2c768ed(%rip)        #    0xffffffff99cb423c <reset_hung_task>
    0xffffffff9703d94f <watchdog+127>:      test   %eax,%eax
    0xffffffff9703d951 <watchdog+129>:      jne    0xffffffff9703d95c <watchdog+140>
    0xffffffff9703d953 <watchdog+131>:      cmpb   $0x0,0x2c768de(%rip)        #    0xffffffff99cb4238 <hung_detector_suspended>
    0xffffffff9703d95a <watchdog+138>:      je     0xffffffff9703d965 <watchdog+149>
    0xffffffff9703d95c <watchdog+140>:      mov    0x1bca05d(%rip),%rbx        #    0xffffffff98c079c0 <jiffies>
    0xffffffff9703d963 <watchdog+147>:      jmp    0xffffffff9703d8f8 <watchdog+40>
    0xffffffff9703d965 <watchdog+149>:      call   0xffffffff9703d5f0   <check_hung_uninterruptible_tasks>
    0xffffffff9703d96a <watchdog+154>:      jmp    0xffffffff9703d95c <watchdog+140>

- Here we can see that `watchdog` doesn't call `panic` itself, instead it calls `check_hung_uninterruptible_tasks`, where we can assume the `panic` call happens:
`0xffffffff9703d965 <watchdog+149>:      call   0xffffffff9703d5f0 <check_hung_uninterruptible_tasks>`.
---
## `dis check_hung_uninterruptible_tasks`
    0xffffffff9703d5f0 <check_hung_uninterruptible_tasks>:  nopl   0x0(%rax,%rax,1)     [FTRACE NOP]
    0xffffffff9703d5f5 <check_hung_uninterruptible_tasks+5>:        push   %r15
    0xffffffff9703d5f7 <check_hung_uninterruptible_tasks+7>:        push   %r14
    0xffffffff9703d5f9 <check_hung_uninterruptible_tasks+9>:        push   %r13
    0xffffffff9703d5fb <check_hung_uninterruptible_tasks+11>:       push   %r12
    0xffffffff9703d5fd <check_hung_uninterruptible_tasks+13>:       push   %rbp
    0xffffffff9703d5fe <check_hung_uninterruptible_tasks+14>:       push   %rbx
    0xffffffff9703d5ff <check_hung_uninterruptible_tasks+15>:       sub    $0x18,%rsp
    0xffffffff9703d603 <check_hung_uninterruptible_tasks+19>:       mov    0x21434ae    (%rip),%r15d        # 0xffffffff99180ab8 <sysctl_hung_task_check_count>
    0xffffffff9703d60a <check_hung_uninterruptible_tasks+26>:       mov    0x1bca3af    (%rip),%r13        # 0xffffffff98c079c0 <jiffies>
    0xffffffff9703d611 <check_hung_uninterruptible_tasks+33>:       mov    %rdi,0x8(%rsp)
    0xffffffff9703d616 <check_hung_uninterruptible_tasks+38>:       mov    $0x7,%edi
    0xffffffff9703d61b <check_hung_uninterruptible_tasks+43>:       call    0xffffffff96f0b550 <test_taint>
    0xffffffff9703d620 <check_hung_uninterruptible_tasks+48>:       or     0x214347a    (%rip),%eax        # 0xffffffff99180aa0 <did_panic>
    0xffffffff9703d626 <check_hung_uninterruptible_tasks+54>:       je      0xffffffff9703d63b <check_hung_uninterruptible_tasks+75>
    0xffffffff9703d628 <check_hung_uninterruptible_tasks+56>:       add    $0x18,%rsp
    0xffffffff9703d62c <check_hung_uninterruptible_tasks+60>:       pop    %rbx
    0xffffffff9703d62d <check_hung_uninterruptible_tasks+61>:       pop    %rbp
    0xffffffff9703d62e <check_hung_uninterruptible_tasks+62>:       pop    %r12
    0xffffffff9703d630 <check_hung_uninterruptible_tasks+64>:       pop    %r13
    0xffffffff9703d632 <check_hung_uninterruptible_tasks+66>:       pop    %r14
    0xffffffff9703d634 <check_hung_uninterruptible_tasks+68>:       pop    %r15
    0xffffffff9703d636 <check_hung_uninterruptible_tasks+70>:       ret
    0xffffffff9703d637 <check_hung_uninterruptible_tasks+71>:       int3
    0xffffffff9703d638 <check_hung_uninterruptible_tasks+72>:       int3
    0xffffffff9703d639 <check_hung_uninterruptible_tasks+73>:       int3
    0xffffffff9703d63a <check_hung_uninterruptible_tasks+74>:       int3
    0xffffffff9703d63b <check_hung_uninterruptible_tasks+75>:       call    0xffffffff96fb3be0 <__rcu_read_lock>
    0xffffffff9703d640 <check_hung_uninterruptible_tasks+80>:       mov    0x1bddc49    (%rip),%r12        # 0xffffffff98c1b290 <init_task+2512>
    0xffffffff9703d647 <check_hung_uninterruptible_tasks+87>:       lea    -0x9d0(%r12),    %rax
    0xffffffff9703d64f <check_hung_uninterruptible_tasks+95>:       mov    %rax,0x10    (%rsp)
    0xffffffff9703d654 <check_hung_uninterruptible_tasks+100>:      cmp     $0xffffffff98c1b290,%r12
    0xffffffff9703d65b <check_hung_uninterruptible_tasks+107>:      je      0xffffffff9703d7fe <check_hung_uninterruptible_tasks+526>
    0xffffffff9703d661 <check_hung_uninterruptible_tasks+113>:      mov    $0x64,%ebp
    0xffffffff9703d666 <check_hung_uninterruptible_tasks+118>:      mov    0x338(%r12), %rax
    0xffffffff9703d66e <check_hung_uninterruptible_tasks+126>:      mov    0x10(%rax),  %rsi
    0xffffffff9703d672 <check_hung_uninterruptible_tasks+130>:      add    $0x10,%rax
    0xffffffff9703d676 <check_hung_uninterruptible_tasks+134>:      lea    -0xb58(%rsi),    %rbx
    0xffffffff9703d67d <check_hung_uninterruptible_tasks+141>:      cmp    %rax,%rsi
    0xffffffff9703d680 <check_hung_uninterruptible_tasks+144>:      je      0xffffffff9703d7d8 <check_hung_uninterruptible_tasks+488>
    0xffffffff9703d686 <check_hung_uninterruptible_tasks+150>:      lea    -0x1(%r15),  %r14d
    0xffffffff9703d68a <check_hung_uninterruptible_tasks+154>:      test   %r15d,%r15d
    0xffffffff9703d68d <check_hung_uninterruptible_tasks+157>:      jne     0xffffffff9703d6d2 <check_hung_uninterruptible_tasks+226>
    0xffffffff9703d68f <check_hung_uninterruptible_tasks+159>:      jmp     0xffffffff9703d7fe <check_hung_uninterruptible_tasks+526>
    0xffffffff9703d694 <check_hung_uninterruptible_tasks+164>:      mov    0x20(%rbx),  %eax
    0xffffffff9703d697 <check_hung_uninterruptible_tasks+167>:      and    $0x502,%eax
    0xffffffff9703d69c <check_hung_uninterruptible_tasks+172>:      cmp    $0x2,%eax
    0xffffffff9703d69f <check_hung_uninterruptible_tasks+175>:      je      0xffffffff9703d7ad <check_hung_uninterruptible_tasks+445>
    0xffffffff9703d6a5 <check_hung_uninterruptible_tasks+181>:      mov    0x338(%r12), %rax
    0xffffffff9703d6ad <check_hung_uninterruptible_tasks+189>:      mov    0xb58(%rbx), %rsi
    0xffffffff9703d6b4 <check_hung_uninterruptible_tasks+196>:      add    $0x10,%rax
    0xffffffff9703d6b8 <check_hung_uninterruptible_tasks+200>:      lea    -0xb58(%rsi),    %rbx
    0xffffffff9703d6bf <check_hung_uninterruptible_tasks+207>:      cmp    %rax,%rsi
    0xffffffff9703d6c2 <check_hung_uninterruptible_tasks+210>:      je      0xffffffff9703d7d5 <check_hung_uninterruptible_tasks+485>
    0xffffffff9703d6c8 <check_hung_uninterruptible_tasks+216>:      sub    $0x1,%r14d
    0xffffffff9703d6cc <check_hung_uninterruptible_tasks+220>:      jb      0xffffffff9703d7fe <check_hung_uninterruptible_tasks+526>
    0xffffffff9703d6d2 <check_hung_uninterruptible_tasks+226>:      mov    0x1bca2e7    (%rip),%rsi        # 0xffffffff98c079c0 <jiffies>
    0xffffffff9703d6d9 <check_hung_uninterruptible_tasks+233>:      mov    %rbp,%rax
    0xffffffff9703d6dc <check_hung_uninterruptible_tasks+236>:      sub    %rsi,%rax
    0xffffffff9703d6df <check_hung_uninterruptible_tasks+239>:      add    %r13,%rax
    0xffffffff9703d6e2 <check_hung_uninterruptible_tasks+242>:      jns     0xffffffff9703d694 <check_hung_uninterruptible_tasks+164>
    0xffffffff9703d6e4 <check_hung_uninterruptible_tasks+244>:      lea    -0x9a0(%r12),    %r15
    0xffffffff9703d6ec <check_hung_uninterruptible_tasks+252>:      mov    $0x1,%eax
    0xffffffff9703d6f1 <check_hung_uninterruptible_tasks+257>:      lock xadd %eax,-0x9a0   (%r12)
    0xffffffff9703d6fb <check_hung_uninterruptible_tasks+267>:      test   %eax,%eax
    0xffffffff9703d6fd <check_hung_uninterruptible_tasks+269>:      je      0xffffffff9703d87a <check_hung_uninterruptible_tasks+650>
    0xffffffff9703d703 <check_hung_uninterruptible_tasks+275>:      lea    0x1(%rax),%ecx
    0xffffffff9703d706 <check_hung_uninterruptible_tasks+278>:      or     %eax,%ecx
    0xffffffff9703d708 <check_hung_uninterruptible_tasks+280>:      js      0xffffffff9703d847 <check_hung_uninterruptible_tasks+599>
    0xffffffff9703d70e <check_hung_uninterruptible_tasks+286>:      lea    0x30(%rbx),  %rdi
    0xffffffff9703d712 <check_hung_uninterruptible_tasks+290>:      mov    $0x1,%eax
    0xffffffff9703d717 <check_hung_uninterruptible_tasks+295>:      lock xadd %eax,0x30 (%rbx)
    0xffffffff9703d71c <check_hung_uninterruptible_tasks+300>:      test   %eax,%eax
    0xffffffff9703d71e <check_hung_uninterruptible_tasks+302>:      je      0xffffffff9703d88c <check_hung_uninterruptible_tasks+668>
    0xffffffff9703d724 <check_hung_uninterruptible_tasks+308>:      lea    0x1(%rax),%ecx
    0xffffffff9703d727 <check_hung_uninterruptible_tasks+311>:      or     %eax,%ecx
    0xffffffff9703d729 <check_hung_uninterruptible_tasks+313>:      js      0xffffffff9703d830 <check_hung_uninterruptible_tasks+576>
    0xffffffff9703d72f <check_hung_uninterruptible_tasks+319>:      mov    %rdi,(%rsp)
    0xffffffff9703d733 <check_hung_uninterruptible_tasks+323>:      xor    %r13d,%r13d
    0xffffffff9703d736 <check_hung_uninterruptible_tasks+326>:      call    0xffffffff96fb7c30 <__rcu_read_unlock>
    0xffffffff9703d73b <check_hung_uninterruptible_tasks+331>:      call    0xffffffff97add8f0 <__cond_resched>
    0xffffffff9703d740 <check_hung_uninterruptible_tasks+336>:      call    0xffffffff96fb3be0 <__rcu_read_lock>
    0xffffffff9703d745 <check_hung_uninterruptible_tasks+341>:      mov    (%rsp),%rdi
    0xffffffff9703d749 <check_hung_uninterruptible_tasks+345>:      cmpq   $0x0,0x130   (%r12)
    0xffffffff9703d752 <check_hung_uninterruptible_tasks+354>:      je      0xffffffff9703d763 <check_hung_uninterruptible_tasks+371>
    0xffffffff9703d754 <check_hung_uninterruptible_tasks+356>:      xor    %r13d,%r13d
    0xffffffff9703d757 <check_hung_uninterruptible_tasks+359>:      cmpq   $0x0,0xb00   (%rbx)
    0xffffffff9703d75f <check_hung_uninterruptible_tasks+367>:      setne  %r13b
    0xffffffff9703d763 <check_hung_uninterruptible_tasks+371>:      mov    $0xffffffff, %eax
    0xffffffff9703d768 <check_hung_uninterruptible_tasks+376>:      lock xadd %eax,(%rdi)
    0xffffffff9703d76c <check_hung_uninterruptible_tasks+380>:      cmp    $0x1,%eax
    0xffffffff9703d76f <check_hung_uninterruptible_tasks+383>:      je      0xffffffff9703d7cb <check_hung_uninterruptible_tasks+475>
    0xffffffff9703d771 <check_hung_uninterruptible_tasks+385>:      test   %eax,%eax
    0xffffffff9703d773 <check_hung_uninterruptible_tasks+387>:      jle     0xffffffff9703d859 <check_hung_uninterruptible_tasks+617>
    0xffffffff9703d779 <check_hung_uninterruptible_tasks+393>:      mov    $0xffffffff, %eax
    0xffffffff9703d77e <check_hung_uninterruptible_tasks+398>:      lock xadd %eax,(%r15)
    0xffffffff9703d783 <check_hung_uninterruptible_tasks+403>:      cmp    $0x1,%eax
    0xffffffff9703d786 <check_hung_uninterruptible_tasks+406>:      je      0xffffffff9703d7bf <check_hung_uninterruptible_tasks+463>
    0xffffffff9703d788 <check_hung_uninterruptible_tasks+408>:      test   %eax,%eax
    0xffffffff9703d78a <check_hung_uninterruptible_tasks+410>:      jle     0xffffffff9703d868 <check_hung_uninterruptible_tasks+632>
    0xffffffff9703d790 <check_hung_uninterruptible_tasks+416>:      test   %r13d,%r13d
    0xffffffff9703d793 <check_hung_uninterruptible_tasks+419>:      je      0xffffffff9703d7fe <check_hung_uninterruptible_tasks+526>
    0xffffffff9703d795 <check_hung_uninterruptible_tasks+421>:      mov    0x1bca224    (%rip),%r13        # 0xffffffff98c079c0 <jiffies>
    0xffffffff9703d79c <check_hung_uninterruptible_tasks+428>:      mov    0x20(%rbx),  %eax
    0xffffffff9703d79f <check_hung_uninterruptible_tasks+431>:      and    $0x502,%eax
    0xffffffff9703d7a4 <check_hung_uninterruptible_tasks+436>:      cmp    $0x2,%eax
    0xffffffff9703d7a7 <check_hung_uninterruptible_tasks+439>:      jne     0xffffffff9703d6a5 <check_hung_uninterruptible_tasks+181>
    0xffffffff9703d7ad <check_hung_uninterruptible_tasks+445>:      mov    0x8(%rsp),%rsi
    0xffffffff9703d7b2 <check_hung_uninterruptible_tasks+450>:      mov    %rbx,%rdi
    0xffffffff9703d7b5 <check_hung_uninterruptible_tasks+453>:      call    0xffffffff9703d4a0 <check_hung_task>
    0xffffffff9703d7ba <check_hung_uninterruptible_tasks+458>:      jmp     0xffffffff9703d6a5 <check_hung_uninterruptible_tasks+181>
    0xffffffff9703d7bf <check_hung_uninterruptible_tasks+463>:      mov    0x10(%rsp),  %rdi
    0xffffffff9703d7c4 <check_hung_uninterruptible_tasks+468>:      call    0xffffffff96f07b80 <__put_task_struct>
    0xffffffff9703d7c9 <check_hung_uninterruptible_tasks+473>:      jmp     0xffffffff9703d790 <check_hung_uninterruptible_tasks+416>
    0xffffffff9703d7cb <check_hung_uninterruptible_tasks+475>:      mov    %rbx,%rdi
    0xffffffff9703d7ce <check_hung_uninterruptible_tasks+478>:      call    0xffffffff96f07b80 <__put_task_struct>
    0xffffffff9703d7d3 <check_hung_uninterruptible_tasks+483>:      jmp     0xffffffff9703d779 <check_hung_uninterruptible_tasks+393>
    0xffffffff9703d7d5 <check_hung_uninterruptible_tasks+485>:      mov    %r14d,%r15d
    0xffffffff9703d7d8 <check_hung_uninterruptible_tasks+488>:      mov    0x10(%rsp),  %rax
    0xffffffff9703d7dd <check_hung_uninterruptible_tasks+493>:      mov    0x9d0(%rax), %r12
    0xffffffff9703d7e4 <check_hung_uninterruptible_tasks+500>:      lea    -0x9d0(%r12),    %rax
    0xffffffff9703d7ec <check_hung_uninterruptible_tasks+508>:      mov    %rax,0x10    (%rsp)
    0xffffffff9703d7f1 <check_hung_uninterruptible_tasks+513>:      cmp     $0xffffffff98c1b290,%r12
    0xffffffff9703d7f8 <check_hung_uninterruptible_tasks+520>:      jne     0xffffffff9703d666 <check_hung_uninterruptible_tasks+118>
    0xffffffff9703d7fe <check_hung_uninterruptible_tasks+526>:      call    0xffffffff96fb7c30 <__rcu_read_unlock>
    0xffffffff9703d803 <check_hung_uninterruptible_tasks+531>:      cmpb   $0x0,0x2c76a3e   (%rip)        # 0xffffffff99cb4248 <hung_task_show_all_bt>
    0xffffffff9703d80a <check_hung_uninterruptible_tasks+538>:      jne     0xffffffff9703d8a3 <check_hung_uninterruptible_tasks+691>
    0xffffffff9703d810 <check_hung_uninterruptible_tasks+544>:      cmpb   $0x0,0x2c76a32   (%rip)        # 0xffffffff99cb4249 <hung_task_call_panic>
    0xffffffff9703d817 <check_hung_uninterruptible_tasks+551>:      jne     0xffffffff97a81263 <check_hung_uninterruptible_tasks.cold>
    0xffffffff9703d81d <check_hung_uninterruptible_tasks+557>:      add    $0x18,%rsp
    0xffffffff9703d821 <check_hung_uninterruptible_tasks+561>:      pop    %rbx
    0xffffffff9703d822 <check_hung_uninterruptible_tasks+562>:      pop    %rbp
    0xffffffff9703d823 <check_hung_uninterruptible_tasks+563>:      pop    %r12
    0xffffffff9703d825 <check_hung_uninterruptible_tasks+565>:      pop    %r13
    0xffffffff9703d827 <check_hung_uninterruptible_tasks+567>:      pop    %r14
    0xffffffff9703d829 <check_hung_uninterruptible_tasks+569>:      pop    %r15
    0xffffffff9703d82b <check_hung_uninterruptible_tasks+571>:      ret
    0xffffffff9703d82c <check_hung_uninterruptible_tasks+572>:      int3
    0xffffffff9703d82d <check_hung_uninterruptible_tasks+573>:      int3
    0xffffffff9703d82e <check_hung_uninterruptible_tasks+574>:      int3
    0xffffffff9703d82f <check_hung_uninterruptible_tasks+575>:      int3
    0xffffffff9703d830 <check_hung_uninterruptible_tasks+576>:      mov    $0x1,%esi
    0xffffffff9703d835 <check_hung_uninterruptible_tasks+581>:      mov    %rdi,(%rsp)
    0xffffffff9703d839 <check_hung_uninterruptible_tasks+585>:      call    0xffffffff9743ad40 <refcount_warn_saturate>
    0xffffffff9703d83e <check_hung_uninterruptible_tasks+590>:      mov    (%rsp),%rdi
    0xffffffff9703d842 <check_hung_uninterruptible_tasks+594>:      jmp     0xffffffff9703d72f <check_hung_uninterruptible_tasks+319>
    0xffffffff9703d847 <check_hung_uninterruptible_tasks+599>:      mov    $0x1,%esi
    0xffffffff9703d84c <check_hung_uninterruptible_tasks+604>:      mov    %r15,%rdi
    0xffffffff9703d84f <check_hung_uninterruptible_tasks+607>:      call    0xffffffff9743ad40 <refcount_warn_saturate>
    0xffffffff9703d854 <check_hung_uninterruptible_tasks+612>:      jmp     0xffffffff9703d70e <check_hung_uninterruptible_tasks+286>
    0xffffffff9703d859 <check_hung_uninterruptible_tasks+617>:      mov    $0x3,%esi
    0xffffffff9703d85e <check_hung_uninterruptible_tasks+622>:      call    0xffffffff9743ad40 <refcount_warn_saturate>
    0xffffffff9703d863 <check_hung_uninterruptible_tasks+627>:      jmp     0xffffffff9703d779 <check_hung_uninterruptible_tasks+393>
    0xffffffff9703d868 <check_hung_uninterruptible_tasks+632>:      mov    $0x3,%esi
    0xffffffff9703d86d <check_hung_uninterruptible_tasks+637>:      mov    %r15,%rdi
    0xffffffff9703d870 <check_hung_uninterruptible_tasks+640>:      call    0xffffffff9743ad40 <refcount_warn_saturate>
    0xffffffff9703d875 <check_hung_uninterruptible_tasks+645>:      jmp     0xffffffff9703d790 <check_hung_uninterruptible_tasks+416>
    0xffffffff9703d87a <check_hung_uninterruptible_tasks+650>:      mov    $0x2,%esi
    0xffffffff9703d87f <check_hung_uninterruptible_tasks+655>:      mov    %r15,%rdi
    0xffffffff9703d882 <check_hung_uninterruptible_tasks+658>:      call    0xffffffff9743ad40 <refcount_warn_saturate>
    0xffffffff9703d887 <check_hung_uninterruptible_tasks+663>:      jmp     0xffffffff9703d70e <check_hung_uninterruptible_tasks+286>
    0xffffffff9703d88c <check_hung_uninterruptible_tasks+668>:      mov    $0x2,%esi
    0xffffffff9703d891 <check_hung_uninterruptible_tasks+673>:      mov    %rdi,(%rsp)
    0xffffffff9703d895 <check_hung_uninterruptible_tasks+677>:      call    0xffffffff9743ad40 <refcount_warn_saturate>
    0xffffffff9703d89a <check_hung_uninterruptible_tasks+682>:      mov    (%rsp),%rdi
    0xffffffff9703d89e <check_hung_uninterruptible_tasks+686>:      jmp     0xffffffff9703d72f <check_hung_uninterruptible_tasks+319>
    0xffffffff9703d8a3 <check_hung_uninterruptible_tasks+691>:      xor    %esi,%esi
    0xffffffff9703d8a5 <check_hung_uninterruptible_tasks+693>:      mov     $0xffffffff9917fea0,%rdi
    0xffffffff9703d8ac <check_hung_uninterruptible_tasks+700>:      movb   $0x0,0x2c76995   (%rip)        # 0xffffffff99cb4248 <hung_task_show_all_bt>
    0xffffffff9703d8b3 <check_hung_uninterruptible_tasks+707>:      call    0xffffffff96e73bd0 <arch_trigger_cpumask_backtrace>
    0xffffffff9703d8b8 <check_hung_uninterruptible_tasks+712>:      jmp     0xffffffff9703d810 <check_hung_uninterruptible_tasks+544>
- Not much to see here, we can see the inner workings of `check_hung_uninterruptible_tasks`. Even after digging deeper f.e. `dis test_taint` I was unable to gain any leads, so I had to look elsewhere.
---
## `foreach UN bt` - foreach user namespace backtrace
    PID: 1      TASK: ffff9a20c0264600  CPU: 0   COMMAND: "systemd"
    #0 [ffffbb2900013d70] __schedule at ffffffff97add369
    #1 [ffffbb2900013e08] schedule at ffffffff97add6ce
    #2 [ffffbb2900013e20] schedule_preempt_disabled at ffffffff97addbe1
    #3 [ffffbb2900013e28] rwsem_down_read_slowpath at ffffffff97ae057f
    #4 [ffffbb2900013ec8] down_read at ffffffff97ae0745
    #5 [ffffbb2900013ed8] do_user_addr_fault at ffffffff96e8cb65
    #6 [ffffbb2900013f28] exc_page_fault at ffffffff97ad1d62
    #7 [ffffbb2900013f50] asm_exc_page_fault at ffffffff97c00bb2
        RIP: 00007f1601861cfc  RSP: 00007ffdb255fb80  RFLAGS: 00010246
        RAX: 0000000000000001  RBX: 0000000000000000  RCX: 000000000003f282
        RDX: 000056172528ac80  RSI: 7fffffffffffffff  RDI: 431bde82d7b634db
        RBP: 0000561724f67dc0   R8: 0000000000000006   R9: 00000059d60a512d
        R10: 00007ffdb256b080  R11: 00007ffdb256b0f0  R12: 0000000000000000
        R13: 0000000000000001  R14: 000056172517e240  R15: 0000561724f67c30
        ORIG_RAX: ffffffffffffffff  CS: 0033  SS: 002b

    PID: 3582   TASK: ffff9a20c53aa300  CPU: 1   COMMAND: "bash"
    #0 [ffffbb2901fcf9f0] __schedule at ffffffff97add369
    #1 [ffffbb2901fcfa88] schedule at ffffffff97add6ce
    #2 [ffffbb2901fcfaa0] schedule_preempt_disabled at ffffffff97addbe1
    #3 [ffffbb2901fcfaa8] __mutex_lock.constprop.0 at ffffffff97aded33
    #4 [ffffbb2901fcfb20] take_the_lock_of_power at ffffffffc0dd105e [smajdalf]
    #5 [ffffbb2901fcfb38] proc_sys_call_handler at ffffffff972f7165
    #6 [ffffbb2901fcfb90] vfs_write at ffffffff97249d4b
    #7 [ffffbb2901fcfc20] ksys_write at ffffffff9724a1df
    #8 [ffffbb2901fcfc58] do_syscall_64 at ffffffff97acd45c
    #9 [ffffbb2901fcfc88] get_close_on_exec at ffffffff97273755
    #10 [ffffbb2901fcfca0] do_fcntl at ffffffff97262115
    #11 [ffffbb2901fcfd10] syscall_exit_work at ffffffff96fc8a63
    #12 [ffffbb2901fcfd28] syscall_exit_to_user_mode at ffffffff97ad21f9
    #13 [ffffbb2901fcfd38] do_syscall_64 at ffffffff97acd46b
    #14 [ffffbb2901fcfd58] do_sys_openat2 at ffffffff97245c11
    #15 [ffffbb2901fcfdc0] __handle_mm_fault at ffffffff97196e3b
    #16 [ffffbb2901fcfea0] handle_mm_fault at ffffffff971972f6
    #17 [ffffbb2901fcfed8] do_user_addr_fault at ffffffff96e8c926
    #18 [ffffbb2901fcff28] clear_bhb_loop at ffffffff97c01705
    #19 [ffffbb2901fcff38] clear_bhb_loop at ffffffff97c01705
    #20 [ffffbb2901fcff50] entry_SYSCALL_64_after_hwframe at ffffffff97c00130
        RIP: 00007fec1a93eb47  RSP: 00007ffe39fbc638  RFLAGS: 00000246
        RAX: ffffffffffffffda  RBX: 0000000000000002  RCX: 00007fec1a93eb47
        RDX: 0000000000000002  RSI: 0000562e5aad0300  RDI: 0000000000000001
        RBP: 0000562e5aad0300   R8: 0000000000000000   R9: 00007fec1a9b14e0
        R10: 00007fec1a9b13e0  R11: 0000000000000246  R12: 0000000000000002
        R13: 00007fec1a9fb780  R14: 0000000000000002  R15: 00007fec1a9f69e0
        ORIG_RAX: 0000000000000001  CS: 0033  SS: 002b

    PID: 4589   TASK: ffff9a20c4d28000  CPU: 0   COMMAND: "systemd-tmpfile"
    #0 [ffffbb2900cff890] __schedule at ffffffff97add369
    #1 [ffffbb2900cff928] schedule at ffffffff97add6ce
    #2 [ffffbb2900cff940] schedule_preempt_disabled at ffffffff97addbe1
    #3 [ffffbb2900cff948] rwsem_down_read_slowpath at ffffffff97ae057f
    #4 [ffffbb2900cff9e0] down_read_killable at ffffffff97ae08c5
    #5 [ffffbb2900cff9f0] __access_remote_vm at ffffffff9719761a
    #6 [ffffbb2900cffa68] environ_read at ffffffff972e8742
    #7 [ffffbb2900cffad0] vfs_read at ffffffff972491a4
    #8 [ffffbb2900cffb70] ksys_read at ffffffff9724a08f
    #9 [ffffbb2900cffba8] do_syscall_64 at ffffffff97acd45c
    #10 [ffffbb2900cffbf8] avc_has_perm at ffffffff97344b08
    #11 [ffffbb2900cffc60] selinux_inode_getattr at ffffffff9734fde9
    #12 [ffffbb2900cffd50] __do_sys_newfstatat at ffffffff972516f5
    #13 [ffffbb2900cffe08] do_syscall_64 at ffffffff97acd46b
    #14 [ffffbb2900cffe58] kmem_cache_free at ffffffff971f7dd5
    #15 [ffffbb2900cffe88] do_sys_openat2 at ffffffff97245c11
    #16 [ffffbb2900cffed0] syscall_exit_work at ffffffff96fc8a63
    #17 [ffffbb2900cffee8] syscall_exit_to_user_mode at ffffffff97ad21f9
    #18 [ffffbb2900cffef8] do_syscall_64 at ffffffff97acd46b
    #19 [ffffbb2900cfff18] clear_bhb_loop at ffffffff97c01705
    #20 [ffffbb2900cfff28] clear_bhb_loop at ffffffff97c01705
    #21 [ffffbb2900cfff38] clear_bhb_loop at ffffffff97c01705
    #22 [ffffbb2900cfff50] entry_SYSCALL_64_after_hwframe at ffffffff97c00130
        RIP: 00007fc5a513eaa2  RSP: 00007ffc96f6ba48  RFLAGS: 00000246
        RAX: ffffffffffffffda  RBX: 000055cad0f463e0  RCX: 00007fc5a513eaa2
        RDX: 0000000000000400  RSI: 000055cad0f465c0  RDI: 0000000000000003
        RBP: 00007fc5a51f75e0   R8: 0000000000000003   R9: 0000000000000000
        R10: 0000000000001000  R11: 0000000000000246  R12: 00007fc5a520d308
        R13: 0000000000000d68  R14: 00007fc5a51f69e0  R15: 0000000000000d68
        ORIG_RAX: 0000000000000000  CS: 0033  SS: 002b

- In the hopes of finding a function call that belongs to the module `smajdalf`, I searched the backtraces of every user namespace and found the function `take_the_lock_of_power` being called on CPU1 by the command `bash` and task `ffff9a20c53aa300` with the process id `PID = 3582`:
`#4 [ffffbb2901fcfb20] take_the_lock_of_power at ffffffffc0dd105e [smajdalf]`.
---
## `dis take_the_lock_of_power`
    0xffffffffc0dd1010 <take_the_lock_of_power>:    nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffffc0dd1015 <take_the_lock_of_power+5>:  mov    -0x281b5d8c(%rip),%rax           # 0xffffffff98c1b290 <init_task+2512>
    0xffffffffc0dd101c <take_the_lock_of_power+12>: push   %rbp
    0xffffffffc0dd101d <take_the_lock_of_power+13>: push   %rbx
    0xffffffffc0dd101e <take_the_lock_of_power+14>: cmp    $0xffffffff98c1b290,%rax
    0xffffffffc0dd1024 <take_the_lock_of_power+20>: je     0xffffffffc0dd102f   <take_the_lock_of_power+31>
    0xffffffffc0dd1026 <take_the_lock_of_power+22>: cmpl   $0x1,0xc8(%rax)
    0xffffffffc0dd102d <take_the_lock_of_power+29>: je     0xffffffffc0dd1067   <take_the_lock_of_power+87>
    0xffffffffc0dd102f <take_the_lock_of_power+31>: movabs $0x1bf08eaff,%rbx
    0xffffffffc0dd1039 <take_the_lock_of_power+41>: pause
    0xffffffffc0dd103b <take_the_lock_of_power+43>: call   0xffffffff97add8f0   <__cond_resched>
    0xffffffffc0dd1040 <take_the_lock_of_power+48>: sub    $0x1,%rbx
    0xffffffffc0dd1044 <take_the_lock_of_power+52>: jne    0xffffffffc0dd1039   <take_the_lock_of_power+41>
    0xffffffffc0dd1046 <take_the_lock_of_power+54>: mov    $0xffffffffc0dd9120,%rdi
    0xffffffffc0dd104d <take_the_lock_of_power+61>: call   0xffffffff97adf090   <mutex_lock>
    0xffffffffc0dd1052 <take_the_lock_of_power+66>: mov    $0xffffffffc0dd9120,%rdi
    0xffffffffc0dd1059 <take_the_lock_of_power+73>: call   0xffffffff97adf090   <mutex_lock>
    0xffffffffc0dd105e <take_the_lock_of_power+78>: xor    %eax,%eax
    0xffffffffc0dd1060 <take_the_lock_of_power+80>: pop    %rbx
    0xffffffffc0dd1061 <take_the_lock_of_power+81>: pop    %rbp
    0xffffffffc0dd1062 <take_the_lock_of_power+82>: ret
    0xffffffffc0dd1063 <take_the_lock_of_power+83>: int3
    0xffffffffc0dd1064 <take_the_lock_of_power+84>: int3
    0xffffffffc0dd1065 <take_the_lock_of_power+85>: int3
    0xffffffffc0dd1066 <take_the_lock_of_power+86>: int3
    0xffffffffc0dd1067 <take_the_lock_of_power+87>: mov    0x50(%rax),%rbp
    0xffffffffc0dd106b <take_the_lock_of_power+91>: xchg   %ax,%ax
    0xffffffffc0dd106d <take_the_lock_of_power+93>: lea    0x70(%rbp),%rdi
    0xffffffffc0dd1071 <take_the_lock_of_power+97>: call   0xffffffff97ae0e60   <down_write>
    0xffffffffc0dd1076 <take_the_lock_of_power+102>:        xchg   %ax,%ax
    0xffffffffc0dd1078 <take_the_lock_of_power+104>:        jmp    0xffffffffc0dd102f <take_the_lock_of_power+31>
    0xffffffffc0dd107a <take_the_lock_of_power+106>:        mov    $0x1,%esi
    0xffffffffc0dd107f <take_the_lock_of_power+111>:        mov    %rbp,%rdi
    0xffffffffc0dd1082 <take_the_lock_of_power+114>:        call   0xffffffff9718b9e0 <__mmap_lock_do_trace_start_locking>
    0xffffffffc0dd1087 <take_the_lock_of_power+119>:        jmp    0xffffffffc0dd106d   <take_the_lock_of_power+93>
    0xffffffffc0dd1089 <take_the_lock_of_power+121>:        mov    $0x1,%edx
    0xffffffffc0dd108e <take_the_lock_of_power+126>:        mov    $0x1,%esi
    0xffffffffc0dd1093 <take_the_lock_of_power+131>:        mov    %rbp,%rdi
    0xffffffffc0dd1096 <take_the_lock_of_power+134>:        call   0xffffffff9718b8c0 <__mmap_lock_do_trace_acquire_returned>
    0xffffffffc0dd109b <take_the_lock_of_power+139>:        jmp    0xffffffffc0dd102f   <take_the_lock_of_power+31>
    0xffffffffc0dd109d <take_the_lock_of_power+141>:        nopl   (%rax)

- Taking a closer look at the `take_the_lock_of_power`, we can see something interesting, the function `mutex_lock` is being called twice in a row with the same argument being passed (`0xffffffffc0dd9120` in `rdi`), which could be the cause of the problem, causing a deadlock and therefore being unable to progress for more than 120 seconds, which `watchdog` will see and indirectly call panic:
```
    0xffffffffc0dd1046 <take_the_lock_of_power+54>: mov    $0xffffffffc0dd9120,%rdi
    0xffffffffc0dd104d <take_the_lock_of_power+61>: call   0xffffffff97adf090   <mutex_lock>
    0xffffffffc0dd1052 <take_the_lock_of_power+66>: mov    $0xffffffffc0dd9120,%rdi
    0xffffffffc0dd1059 <take_the_lock_of_power+73>: call   0xffffffff97adf090   <mutex_lock>
```
- The interesting parts to look at will be the `mutex_lock` itself and the pointer that is being passed into `mutex_lock` in the register `rdi` -> `0xffffffffc0dd9120`.
- Again, nice reference :).
---
## `dis 0xffffffff97adf090` (mutex_lock function)
    0xffffffff97adf090 <mutex_lock>:        nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffff97adf095 <mutex_lock+5>:      push   %rbp
    0xffffffff97adf096 <mutex_lock+6>:      mov    %rdi,%rbp
    0xffffffff97adf099 <mutex_lock+9>:      call   0xffffffff97add8f0 <__cond_resched>
    0xffffffff97adf09e <mutex_lock+14>:     xor    %eax,%eax
    0xffffffff97adf0a0 <mutex_lock+16>:     mov    %gs:0x32a00,%rdx
    0xffffffff97adf0a9 <mutex_lock+25>:     lock cmpxchg %rdx,0x0(%rbp)
    0xffffffff97adf0af <mutex_lock+31>:     jne    0xffffffff97adf0b7 <mutex_lock+39>
    0xffffffff97adf0b1 <mutex_lock+33>:     pop    %rbp
    0xffffffff97adf0b2 <mutex_lock+34>:     ret
    0xffffffff97adf0b3 <mutex_lock+35>:     int3
    0xffffffff97adf0b4 <mutex_lock+36>:     int3
    0xffffffff97adf0b5 <mutex_lock+37>:     int3
    0xffffffff97adf0b6 <mutex_lock+38>:     int3
    0xffffffff97adf0b7 <mutex_lock+39>:     mov    %rbp,%rdi
    0xffffffff97adf0ba <mutex_lock+42>:     pop    %rbp
    0xffffffff97adf0bb <mutex_lock+43>:     jmp    0xffffffff97adf070 <__mutex_lock_slowpath>

- When we take a look at `mutex_lock`, we can see that the passed argument in `rdi` is a pointer to a `struct mutex` that is being locked, it is being stored in `rbp`:
`0xffffffff97adf096 <mutex_lock+6>:      mov    %rdi,%rbp`.
- `mutex_lock` attempts a `cmpxchg` to acquire the lock, however if the lock is already held (`cmpxchg` will fail),  it jumps to the slowpath (`__mutex_lock_slowpath`):
`0xffffffff97adf0a9 <mutex_lock+25>:     lock cmpxchg %rdx,0x0(%rbp)`
`0xffffffff97adf0af <mutex_lock+31>:     jne    0xffffffff97adf0b7 <mutex_lock+39>`
- Since mutexes are not recursive in Linux, we can safely assume, that the two consecutive calls of `mutex_lock` with the same argument access the same pointer (`struct mutex`) and attempt to lock it, creating a deadlock since the struct is not unlocked between the calls.
---
## sym `0xffffffffc0dd9120` (argument passed into `mutex_lock`)
    ffffffffc0dd9120 (?) magic_mutex [smajdalf]

- If we map the pointer that was passed to `mutex_lock` we get the name of the mutex that caused the deadlock in the first place. Its name being `magic_mutex` in the kernel module `smajdalf`.
- Knowing the cause of the deadlock, to avoid we would have unlock the mutex after the first call of `mutex_lock`, insuring we don't try to lock the same mutex twice without unlocking it.
---
## Recap of what we have discovered
- We learned that the panic happened on `CPU1` [1] as well as the actual problem (deadlock)[2].  
- The task that called the panic was `ffff9a2232e30000` [1], the task where the problem occurred was `ffff9a20c53aa300` [2].
- The PID where the panic occurred was `47` [1], the PID where the problem occurred was `3582` [2], blocking the PID `1`.
- The command on which the panic occurred was `khungtaskd` [1], the command where the problem occurred was `bash` [2], ultimately blocking the process `systemd`.
- { [**1**] - Initial output when running `crash`, [**2**] - `foreach UN bt` }
- The kernel panicked because the `khungtaskd` watchdog detected a hung task `systemd` with `PID = 1` (no progress in a set time, by default 120 seconds). It was caused by a deadlock that occurred by attempting to lock the same mutex (`magic_mutex`) twice in a row without unlocking it in between. This is a typical deadlock scenario where a process locks a mutex but then attempts to lock it again, leading to the task being stuck. After 122 seconds of no progress on the process `systemd`, the watchdog indirectly panicked the kernel. The code path was: `watchdog_timer_fn -> panic`
- The lock was a mutex with the name `magic_mutex` from the `smajdalf` kernel module. Its address is `0xffffffffc0dd9120`, which is being passed into the `mutex_lock` function by the `take_the_lock_of_power` function in the `smajdalf` kernel module. The process `systemd` was blocked because it attempted to lock the mutex without unlocking it first, causing the deadlock.
- The lock belongs to the `struct mutex` data structure and locks the function `take_the_lock_of_power` in the `smajdalf` kernel module during the command `bash` on `CPU1`.
- To avoid this kind of kernel panic in the future, we would need to ensure, that the mutex `magic_mutex` is being unlocked before attempting to lock it. Currently we are consecutively calling the `mutex_lock` function twice, with the same argument (pointer to mutex struct), without unlocking it in between the `mutex_lock` calls.
---
# 2. System state at the Crash

## `kmem -i`
                 PAGES        TOTAL      PERCENTAGE
    TOTAL MEM  1967124       7.5 GB         ----
         FREE  1717034       6.5 GB   87% of TOTAL MEM
         USED   250090     976.9 MB   12% of TOTAL MEM
       SHARED    17897      69.9 MB    0% of TOTAL MEM
      BUFFERS      416       1.6 MB    0% of TOTAL MEM
       CACHED   162660     635.4 MB    8% of TOTAL MEM
         SLAB    24170      94.4 MB    1% of TOTAL MEM

    TOTAL HUGE        0            0         ----
     HUGE FREE        0            0    0% of TOTAL HUGE

    TOTAL SWAP        0            0         ----
     SWAP USED        0            0    0% of TOTAL SWAP
     SWAP FREE        0            0    0% of TOTAL SWAP

    COMMIT LIMIT   983562       3.8 GB         ----
      COMMITTED    87929     343.5 MB    8% of TOTAL LIMIT

- We can see that the panic was most likely not memory related, since the system had plenty of free memory (`87%`), low memory utilization (`12%`) and load (from the initial output of `crash`):
`FREE  1717034       6.5 GB   87% of TOTAL MEM`,
`USED   250090     976.9 MB   12% of TOTAL MEM`,
`LOAD AVERAGE: 2.64, 1.20, 0.46`.
- No swap occurred since there was enough free RAM:
```
    TOTAL SWAP        0            0         ----
     SWAP USED        0            0    0% of TOTAL SWAP
     SWAP FREE        0            0    0% of TOTAL SWAP
```
---
## `ps -S`
    RU: 7
    UN: 3
    IN: 124
    ID: 79

- Here we can see the number of processes for each state:
`RU` = `Runnable (running)`          : **7**,
`UN` = `Uninterruptible sleep (I/O)` : **3**,
`IN` = `Interruptible sleep`         : **124**,
`ID` = `Idle`                        : **79**.
In total : **213** processes.
- The same as the number of running tasks in **Initial output when running `crash`**:
`TASKS: 213`.
---
## `runq` - runqueue
    CPU 0 RUNQUEUE: ffff9a2237c339c0
      CURRENT: PID: 0      TASK: ffffffff98c1a8c0  COMMAND: "swapper/0"
      RT PRIO_ARRAY: ffff9a2237c33c80
         [no tasks queued]
      CFS RB_ROOT: ffff9a2237c33a80
         [no tasks queued]

    CPU 1 RUNQUEUE: ffff9a2237cb39c0
      CURRENT: PID: 47     TASK: ffff9a2232e30000  COMMAND: "khungtaskd"
      RT PRIO_ARRAY: ffff9a2237cb3c80
         [no tasks queued]
      CFS RB_ROOT: ffff9a2237cb3a80
         [139] PID: 54     TASK: ffff9a20c1174600  COMMAND: "khugepaged"
         [120] PID: 4626   TASK: ffff9a20c2608000  COMMAND: "kworker/1:1"

    CPU 2 RUNQUEUE: ffff9a2237d339c0
      CURRENT: PID: 0      TASK: ffff9a20c0380000  COMMAND: "swapper/2"
      RT PRIO_ARRAY: ffff9a2237d33c80
         [no tasks queued]
      CFS RB_ROOT: ffff9a2237d33a80
         [no tasks queued]

    CPU 3 RUNQUEUE: ffff9a2237db39c0
      CURRENT: PID: 0      TASK: ffff9a20c0384600  COMMAND: "swapper/3"
      RT PRIO_ARRAY: ffff9a2237db3c80
         [no tasks queued]
      CFS RB_ROOT: ffff9a2237db3a80
         [no tasks queued]

- We can see additional information here, `CPU1` is the only CPU to have queued up processes, indicating that the problem is on `CPU1`. It appears it got stuck during the command `khungtaskd`.
- `CPU0`, `CPU2` and `CPU3` all seem to be fine.