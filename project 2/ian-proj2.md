
# IAN projekt 2 2025

Protokol k druhému projektu do předmetu IAN v roce 2024/2025.

## Crash analysis
Cílem je zjistit příčinu pádu systému analýzou souboru vmcore, vygenerovaným panikou jádra, která byla způsobena vlasntím modulem jádra `smajdalf`.

### Crash
```bash
crash vmlinux-5.14.0-503.15.1.el9_5.x86_64 vmcore
```

Prvním krokem je zahájení analýzy příkazem `crash`, kterému je předán jako argument obraz jádra a dump paměti při pádu systému.

### System info

```bash
crash> sys
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

```

Z informací o systémových datech (panic string `"Kernel panic - not syncing: hung_task: blocked tasks"`) je zřejmé, že došlo k panice kernelu kvůli problému se synchronizací - hung_task. Tzn. že určitá úloha (vlákno či proces) byla zablokovaná déle, než je časový limit mechanismu systému, který detekuje potenciálně zaseknuté úlohy.

Důsledkem může být neefektivní využití zdrojů, či až úplně zablokování systému, protože systém může neomezeně čekat na uvolnění zdrojů.

Příčinou často bývá uváznutí při přístupu ke zdrojům s výlučným přístupem, tzv. *deadlock*.

Další podstatnou informací je, že jádro systému má příznak **TAINTED**, který značí, že jádro bylo ovlivněno neoficiálními nebo neověřenými moduly, změnami či komponentami, které nejsou součástí standardního jádra.
Tudíž tento příznak indikuje možnou nestabilitu systému, protože změny, které vedly k jeho nastavení, mohou ovlivnit stabilitu a správné fungování systému.

```bash
crash> sys -t
TAINTED_MASK: 3001  POE
```

Lze si zobrazit `TAINTED_MASK`, ohledně informací o označení jádra.

Jsou tu konkrétně příznaky `POE`:
- P - Proprietární modul
- O - Out of tree, tzn. modul není součástí standardního jádra
- E - External, neboli experimentální kód, který není běžně podporován


Dále lze vyčíst PID `47` procesu, který vyvolal paniku - příkaz `khungtaskd`, včetně adresy `ffff9a2232e30000` na jeho task_struct.

Panika nastala na CPU `1`.

Stav `TASK_RUNNING (PANIC)` značí, že úloha běží, ale byla detekována panika.

Systém bežel 8 minut a 12 sekund.

Zbytek informací nenaznačuje nic neobvyklého.

```bash
crash> kmem -i
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

```

### Ověření stavu hung_task_panic

```bash
crash> p sysctl_hung_task_panic
sysctl_hung_task_panic = $1 = 1
```

Nyní je opravdu jisté, že `hung_task_panic` byl zapnutý, tzn. že po detekci zaseknutého procesu kernel vyvolal `panic`.

### Backtrace

```bash
crash> bt -l
PID: 47       TASK: ffff9a2232e30000  CPU: 1    COMMAND: "khungtaskd"
 #0 [ffffbb29001a7d18] machine_kexec at ffffffff96e7a897
    /usr/src/debug/kernel-5.14.0-503.15.1.el9_5/linux-5.14.0-503.15.1.el9_5.x86_64/arch/x86/kernel/machine_kexec_64.c: 360
 #1 [ffffbb29001a7d70] __crash_kexec at ffffffff96ffaeaa
    /usr/src/debug/kernel-5.14.0-503.15.1.el9_5/linux-5.14.0-503.15.1.el9_5.x86_64/./include/linux/atomic/atomic-arch-fallback.h: 265
 #2 [ffffbb29001a7e30] panic at ffffffff97a74ce7
    /usr/src/debug/kernel-5.14.0-503.15.1.el9_5/linux-5.14.0-503.15.1.el9_5.x86_64/kernel/panic.c: 250
 #3 [ffffbb29001a7f00] watchdog at ffffffff9703d96a
    /usr/src/debug/kernel-5.14.0-503.15.1.el9_5/linux-5.14.0-503.15.1.el9_5.x86_64/kernel/hung_task.c: 377
 #4 [ffffbb29001a7f18] kthread at ffffffff96f38abd
    /usr/src/debug/kernel-5.14.0-503.15.1.el9_5/linux-5.14.0-503.15.1.el9_5.x86_64/kernel/kthread.c: 369
 #5 [ffffbb29001a7f50] ret_from_fork at ffffffff96e03e89
    /usr/src/debug/kernel-5.14.0-503.15.1.el9_5/linux-5.14.0-503.15.1.el9_5.x86_64/arch/x86/entry/entry_64.S: 248

```

Backtracking úlohy `khungtaskd`, která slouží k detekci a správě zaseknutých (hung) úloh, ukazuje, že byla volána funkce `watchdog`, jenž provádí kontroly a obsahuje časový limit (obvykle 120 sekund), po jehož vypršení byla volána samotná funkce `panic`.

Následně jsou volány`__crash_kexec`, `machine_kexec` pro inicializaci crash dumpu a provedení `kexec` pro nabootování do nového kernelu bez nutnosti restartování zařízení.

#### Watchdog timeout

```bash
cat linux-5.14.0-503.15.1.el9_5/proc/sys/kernel/hung_task_timeout_secs
120
```
Časový limit mechanismu `watchdog` byl v době pádu nastaven na `120` sekund.

### Log

```bash
crash> log | tail -n 45
[    5.009991] block dm-0: the capability attribute has been deprecated.
[  277.000573] smajdalf: loading out-of-tree module taints kernel.
[  277.000584] smajdalf: module license 'RH-EDU' taints kernel.
[  277.000588] Disabling lock debugging due to kernel taint
[  277.000590] smajdalf: module verification failed: signature and/or required key missing - tainting kernel
[  277.000592] smajdalf: module license taints kernel.
[  277.001905] Smajdalf: Carodej nikdy nechodi pozde.
[  492.326391] INFO: task systemd:1 blocked for more than 122 seconds.
[  492.326437]       Tainted: P           OE     -------  ---  5.14.0-503.15.1.el9_5.x86_64 #1
[  492.326462] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  492.326484] task:systemd         state:D stack:0     pid:1     tgid:1     ppid:0      flags:0x00000002
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
[  492.326987] CPU: 1 PID: 47 Comm: khungtaskd Kdump: loaded Tainted: P           OE     -------  ---  5.14.0-503.15.1.el9_5.x86_64 #1
[  492.327022] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-1.fc39 04/01/2014
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
```

Log kernel ring bufferu obsahuje důležité informace jako:
- Načtení neznámého modulu `smajdalf`, který "označil" jádro
- Úloha systemd byla blokována déle než `122` sekund
- Panika kernelu `Kernel panic - not syncing: hung_task: blocked tasks` v čase `492.326967 (8 min 12.326967 s)`
- Call trace úloh

V backtrace blokované úlohy `systemd` se objevují funkce jako `__schedule` a `schedule`, které se používají pro blokování procesů či vláken, pokud čekají na nějaký zdroj. Dále funkce `schedule_preempt_disabled` naznačuje, že byla preempce deaktivována.

`rwsem_down_read_slowpath` souvisí s operacemi čtení/zápis nad semafory. `down_read`blokuje aktuální vlákno, pokud nemůže okamžitě získat zámek pro čtení, pokud ho například zamknul jiný proces.

Na základě těchto informací, lze usoudit, že došlo k blokování při pokusu o přístup k nějakému zdroji, zablokovaného zámkem.

Blokování trvalo déle než `122` sekund (více než limit watchdogu ~ `120` s), což vyústilo v detekci problému a panikou jádra, jelikož se systém nemohl zotavit.

### Tainted modules

```bash
crash> mod -t
NAME      TAINTS
smajdalf  POE
```

V log bufferu jsou informace o` kernel taint` kvůli načtení modulu `smajdalf`. Příkazem `mod -t` to lze dodatečně ověřit.

### Module symbol table

```bash
crash> sym -m smajdalf
ffffffffc0dd1000 MODULE TEXT START: smajdalf
ffffffffc0dd1000 (t) __pfx_take_the_lock_of_power
ffffffffc0dd1010 (t) take_the_lock_of_power
ffffffffc0dd10a0 (T) __pfx_trik_se_spicatym_kloboukem
ffffffffc0dd10b0 (T) trik_se_spicatym_kloboukem
ffffffffc0dd10cd (T) __pfx_cleanup_module
ffffffffc0dd10dd (t) smajdalf_cleanup
ffffffffc0dd10dd (T) cleanup_module
ffffffffc0dd2000 MODULE TEXT END: smajdalf
ffffffffc0dd9000 MODULE DATA START: smajdalf
ffffffffc0dd9020 (?) smajdalf_dir_table
ffffffffc0dd90a0 (?) smajdalf_table
ffffffffc0dd9120 (?) magic_mutex
ffffffffc0dd9140 (?) __UNIQUE_ID___addressable_cleanup_module295
ffffffffc0dd9148 (?) _entry_ptr.0
ffffffffc0dd9150 (?) _entry_ptr.1
ffffffffc0dd9180 (?) __this_module
ffffffffc0dd9700 (?) smajdalf_sysctl_header
ffffffffc0dda000 MODULE DATA END: smajdalf
ffffffffc0ddb000 MODULE RODATA START: smajdalf
ffffffffc0ddb024 (?) _note_10
ffffffffc0ddb03c (?) _note_9
ffffffffc0ddb100 (?) __func__.26
ffffffffc0ddb120 (?) _entry.25
ffffffffc0ddb150 (?) __func__.24
ffffffffc0ddb160 (?) _entry.23
ffffffffc0ddc000 MODULE RODATA END: smajdalf
ffffffffc0de3000 MODULE RO_AFTER_INIT START: smajdalf
ffffffffc0de4000 MODULE RO_AFTER_INIT END: smajdalf
```

Vzhledem k tomu, že je modul `smajdalf` na základě předchozích informací podezřelý, je nutné analyzovat dostupné informace o něm.

Tabulka symbolů si o něm vede záznam a poskytuje informace o jeho funkcích v sekci `MODULE TEXT` a o datových strukturách v sekci `MODULE DATA`.

Proběhne analýza funkcí:
- `take_the_lock_of_power`
- `trik_se_spicatym_kloboukem`

a datový struktur:
- `smajdalf_dir_table` - struktura sysctl
- `smajdalf_table` - struktura sysctl
- `magic_mutex` - struktura mutex, základní zamykací primitivum
- `smajdalf_sysctl_header` - pravděpodobně ukazatel na záhlaví struktury sysctl

### ctl_table structure

```bash
crash> whatis struct ctl_table_header
struct ctl_table_header {
    union {
        struct {
            struct ctl_table *ctl_table;
            int used;
            int count;
            int nreg;
        };
        struct callback_head rcu;
    };
    struct completion *unregistering;
    struct ctl_table *ctl_table_arg;
    struct ctl_table_root *root;
    struct ctl_table_set *set;
    struct ctl_dir *parent;
    struct ctl_node *node;
    struct hlist_head inodes;
}
SIZE: 80
```

```bash
crash> whatis struct ctl_table
struct ctl_table {
    const char *procname;
    void *data;
    int maxlen;
    umode_t mode;
    struct ctl_table *child;
    proc_handler *proc_handler;
    struct ctl_table_poll *poll;
    void *extra1;
    void *extra2;
}
SIZE: 64
```

`ctl_table` je struktura, která slouží k definici parametrů dostupných přes `sysctl` rozhraní (`/proc/sys`), umožňující dynamicky číst a měnit nastavení jádra za běhu systému.

Struktura může mít svůj tzv. `handler`, což je ukazatel na funkci, která se stará o čtení a zápis přes zvolené rozhraní.

Struktury do sebe mohou být zanořené.

Při načítání modulu se volá funkce `register_sysctl_table` (výsledek se přiřadí do zmíněné struktury `smajdalf_sysctl_header`), která projede hierarchii `ctl_table struktur` od předané rodičovské struktury, v tomto případě `smajdalf_dir_table`. Následně je každá položka zaregistrována do virtuálního souborového systému `/proc/sys` a ke každé položce se přiřadí handler, například `/proc/sys/smajdalf/trik_se_spicatym_kloboukem`. 

```bash
crash> struct ctl_table_header smajdalf_sysctl_header
struct ctl_table_header {
  {
    {
      ctl_table = 0xffff9a20c2977a80,
      used = 0,
      count = 0,
      nreg = 0
    },
    rcu = {
      next = 0xffff9a20c2977a80,
      func = 0x0
    }
  },
  unregistering = 0x0,
  ctl_table_arg = 0x2000100000001,
  root = 0xffffffffc0ddb024 <_note_10>,
  set = 0x18,
  parent = 0x200010000000a,
  node = 0xffffffffc0ddb03c <_note_9>,
  inodes = {
    first = 0x34
  }
}

```

```bash
crash> struct ctl_table smajdalf_dir_table
struct ctl_table {
  procname = 0xffffffffc0ddb1a6 <_entry.23+70> "spellbook",
  data = 0x0,
  maxlen = 0,
  mode = 365,
  child = 0xffffffffc0dd90a0 <smajdalf_table>,
  proc_handler = 0x0,
  poll = 0x0,
  extra1 = 0x0,
  extra2 = 0x0
}
```

`smajdalf_dir_table` slouží pouze jako adresář struktur `ctl_table`, ukazatel child obsahuje adresu `smajdalf_table`. Jde si povšimnout, že nemá žádný handler a název sysctl entry je `spellbook`.

```bash
crash> struct ctl_table smajdalf_table
struct ctl_table {
  procname = 0xffffffffc0ddb1b0 <_entry.23+80> "trik_se_spicatym_kloboukem",
  data = 0x0,
  maxlen = 0,
  mode = 128,
  child = 0x0,
  proc_handler = 0xffffffffc0dd1010 <take_the_lock_of_power>,
  poll = 0x0,
  extra1 = 0x0,
  extra2 = 0x0
}
```

`smajdalf_table` obsahuje handler `take_the_lock_of_power` a sysctl entry `trik_se_spicatym_kloboukem`. 

### Functions disassembly

```bash
crash> dis take_the_lock_of_power
0xffffffffc0dd1010 <take_the_lock_of_power>:    nopl   0x0(%rax,%rax,1) [FTRACE NOP]
0xffffffffc0dd1015 <take_the_lock_of_power+5>:  mov    -0x281b5d8c(%rip),%rax        # 0xffffffff98c1b290 <init_task+2512>
0xffffffffc0dd101c <take_the_lock_of_power+12>: push   %rbp
0xffffffffc0dd101d <take_the_lock_of_power+13>: push   %rbx
0xffffffffc0dd101e <take_the_lock_of_power+14>: cmp    $0xffffffff98c1b290,%rax
0xffffffffc0dd1024 <take_the_lock_of_power+20>: je     0xffffffffc0dd102f <take_the_lock_of_power+31>
0xffffffffc0dd1026 <take_the_lock_of_power+22>: cmpl   $0x1,0xc8(%rax)
0xffffffffc0dd102d <take_the_lock_of_power+29>: je     0xffffffffc0dd1067 <take_the_lock_of_power+87>
0xffffffffc0dd102f <take_the_lock_of_power+31>: movabs $0x1bf08eaff,%rbx
0xffffffffc0dd1039 <take_the_lock_of_power+41>: pause  
0xffffffffc0dd103b <take_the_lock_of_power+43>: call   0xffffffff97add8f0 <__cond_resched>
0xffffffffc0dd1040 <take_the_lock_of_power+48>: sub    $0x1,%rbx
0xffffffffc0dd1044 <take_the_lock_of_power+52>: jne    0xffffffffc0dd1039 <take_the_lock_of_power+41>
0xffffffffc0dd1046 <take_the_lock_of_power+54>: mov    $0xffffffffc0dd9120,%rdi
0xffffffffc0dd104d <take_the_lock_of_power+61>: call   0xffffffff97adf090 <mutex_lock>
0xffffffffc0dd1052 <take_the_lock_of_power+66>: mov    $0xffffffffc0dd9120,%rdi
0xffffffffc0dd1059 <take_the_lock_of_power+73>: call   0xffffffff97adf090 <mutex_lock>
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
0xffffffffc0dd1071 <take_the_lock_of_power+97>: call   0xffffffff97ae0e60 <down_write>
0xffffffffc0dd1076 <take_the_lock_of_power+102>:        xchg   %ax,%ax
0xffffffffc0dd1078 <take_the_lock_of_power+104>:        jmp    0xffffffffc0dd102f <take_the_lock_of_power+31>
0xffffffffc0dd107a <take_the_lock_of_power+106>:        mov    $0x1,%esi
0xffffffffc0dd107f <take_the_lock_of_power+111>:        mov    %rbp,%rdi
0xffffffffc0dd1082 <take_the_lock_of_power+114>:        call   0xffffffff9718b9e0 <__mmap_lock_do_trace_start_locking>
0xffffffffc0dd1087 <take_the_lock_of_power+119>:        jmp    0xffffffffc0dd106d <take_the_lock_of_power+93>
0xffffffffc0dd1089 <take_the_lock_of_power+121>:        mov    $0x1,%edx
0xffffffffc0dd108e <take_the_lock_of_power+126>:        mov    $0x1,%esi
0xffffffffc0dd1093 <take_the_lock_of_power+131>:        mov    %rbp,%rdi
0xffffffffc0dd1096 <take_the_lock_of_power+134>:        call   0xffffffff9718b8c0 <__mmap_lock_do_trace_acquire_returned>
0xffffffffc0dd109b <take_the_lock_of_power+139>:        jmp    0xffffffffc0dd102f <take_the_lock_of_power+31>
0xffffffffc0dd109d <take_the_lock_of_power+141>:        nopl   (%rax)
```

Ve funkci (handler) `take_the_lock_of_power` se na druhém řádku kopíruje do registru `rax` adresa `0xffffffff98c1b290`, což je zřejmě položka struktury `task_struct` v proměnné `init_task` na offsetu `+2512`. 

Konkrétní položka na daném offestu je:
`struct task_struct *       parent;               /*  2512     8 */`

S obsahem ukazujícím na počátek sebe sama v rámci init_task:
```bash
crash> p init_task.parent
$3 = (struct task_struct *) 0xffffffff98c1a8c0 <init_task>
```

Poté se provede porovnání `$0xffffffff98c1b290,%rax`, které je úspěšné a skočí se na instrukci `0xffffffffc0dd102f <take_the_lock_of_power+31>`.

Tam se do registru `rbx` zkopíruje hodnota `0x1bf08eaff (7499999999 dec)` a provede se instrukce `pause` (signál procesoru, že se jedná o `spin-loop`), následně se zavolá funkce `__cond_resched`, která umožní běh ostatním úlohám. Další instrukcí je dekrementace registru RBX a skok podmíněný rovnosti s nulou na instrukci `<take_the_lock_of_power+41>`, tudíž vzníká smyčka, ve které se volá `__cond_resched`, dokud v `rbx` nebude nula.

Klíčovou částí je avšak část začínající instrukcí `<take_the_lock_of_power+54>` po dokončení smyčky, kde se dvakrát po sobě volá funkce pro uzamčení mutexu s formálním parametrem, který nese adresu `0xffffffff97adf090`, což je adresa již známé proměnné `magic_mutex`.

Nyní víme, že je `magic_mutex` strukturou `struct mutex` a že se nad ní provádí dvakrát po sobě volání `mutex_lock`. V případě, že není zámek odemčen jiným procesem vzniká **deadlock**.

```bash
crash> dis trik_se_spicatym_kloboukem
0xffffffffc0dd10b0 <trik_se_spicatym_kloboukem>:        nopl   0x0(%rax,%rax,1) [FTRACE NOP]
0xffffffffc0dd10b5 <trik_se_spicatym_kloboukem+5>:      mov    $0xffffffffc0dd9120,%rdi
0xffffffffc0dd10bc <trik_se_spicatym_kloboukem+12>:     call   0xffffffff97adf090 <mutex_lock>
0xffffffffc0dd10c1 <trik_se_spicatym_kloboukem+17>:     mov    $0xffffffffc0dd9120,%rdi
0xffffffffc0dd10c8 <trik_se_spicatym_kloboukem+24>:     jmp    0xffffffff97adf090 <mutex_lock>
```

Ve funkci `trik_se_spicatym_kloboukem` se stejně jako v předchozí funkci zamyká pomocí `mutex_lock` struktura `mutex` dvakrát po sobě.

### What is mutex_lock, struct mutex
```bash
crash> whatis mutex_lock
void mutex_lock(struct mutex *);
```

```bash
crash> whatis struct mutex
struct mutex {
    atomic_long_t owner;
    raw_spinlock_t wait_lock;
    struct optimistic_spin_queue osq;
    struct list_head wait_list;
}
SIZE: 32
```

Dodatečné informace k mutexu.

- owner - `ID` vlastníka, které aktuálně vlastní mutex, tzn. proces, který naposledy úspěšně uzamknul daný mutex a má přístup ke kritické sekci. Pokud je `NULL`, tak jej nikdo nevlastní.
- wait_list - Seznam vláken čekajících na uvolnění zdrojů mutexem. Vlákna se do seznamu přidají, pokud žádají o uzamčené zdroje.

### Set radix to hex
```bash
crash> set hex
output radix: 16 (hex)
```
Pomocný příkaz pro výpis v šestnáctkové soustavě.

### Mutex structure

```bash
crash> struct mutex ffffffffc0dd9120
struct mutex {
  owner = {
    counter = 0xffff9a20c53aa301
  },
  wait_lock = {
    raw_lock = {
      {
        val = {
          counter = 0x0
        },
        {
          locked = 0x0,
          pending = 0x0
        },
        {
          locked_pending = 0x0,
          tail = 0x0
        }
      }
    }
  },
  osq = {
    tail = {
      counter = 0x0
    }
  },
  wait_list = {
    next = 0xffffbb2901fcfac0,
    prev = 0xffffbb2901fcfac0
  }
}
```

Z položek struktury mutex lze vyčíst adresu vlastníka mutexu (není `NULL`, takže není odemčený) a adresu čekajících vláken. Lze si povšimnout, že next i prev odkazují na stejnou adresu, což značí, že aktuálně čeká jen jedno vlákno.

#### wait_list
```bash
crash> kmem 0xffffbb2901fcfac0
    PID: 3582
COMMAND: "bash"
   TASK: ffff9a20c53aa300  [THREAD_INFO: ffff9a20c53aa300]
    CPU: 1
  STATE: TASK_UNINTERRUPTIBLE 

   VMAP_AREA         VM_STRUCT                 ADDRESS RANGE                SIZE
ffff9a20c3948438  ffff9a20c2c5bf80  ffffbb2901fcc000 - ffffbb2901fd1000    20480
```

Adresa úlohy se shoduje s adresou vlastníka ve struktuře mutexu.

#### owner
```bash
crash> kmem 0xffff9a20c53aa301
CACHE             OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE  NAME
ffff9a20c01e6c00     8904        212       258     86    32k  task_struct
  SLAB              MEMORY            NODE  TOTAL  ALLOCATED  FREE
  ffffe9ec8414ea00  ffff9a20c53a8000     0      3          2     1
  FREE / [ALLOCATED]
  [ffff9a20c53aa300]

    PID: 3582
COMMAND: "bash"
   TASK: ffff9a20c53aa300  [THREAD_INFO: ffff9a20c53aa300]
    CPU: 1
  STATE: TASK_UNINTERRUPTIBLE 

      PAGE        PHYSICAL      MAPPING       INDEX CNT FLAGS
ffffe9ec8414ea80 1053aa000 dead000000000400        0  0 17ffffc0000000
```

Adresa vlastníka se odkazuje na strukturu task_struct nesoucí informace o úloze.

Úloha má `PID 3582`, běží na `CPU 1` a je ve stavu `TASK_UNINTERRUPTIBLE`.

Úloha je zablokována a čeká na odblokování, což pravděpodobně souvisí s uzamčeným mutexem `magic_mutex`, který také vlastní.

Na základě řádku `COMMAND` se jedná o instanci shellu.

### task backtrace
```bash
crash> bt ffff9a20c53aa300
PID: 3582     TASK: ffff9a20c53aa300  CPU: 1    COMMAND: "bash"
 #0 [ffffbb2901fcfa20] schedule at ffffffff97add369
 #1 [ffffbb2901fcfa88] schedule at ffffffff97add6ce
 #2 [ffffbb2901fcfaa0] schedule_preempt_disabled at ffffffff97addbe1
 #3 [ffffbb2901fcfaa8] mutex_lock.constprop.0 at ffffffff97aded33
 #4 [ffffbb2901fcfb20] take_the_lock_of_power at ffffffffc0dd105e [smajdalf]
 #5 [ffffbb2901fcfb38] proc_sys_call_handler at ffffffff972f7165
 #6 [ffffbb2901fcfb90] vfs_write at ffffffff97249d4b
 #7 [ffffbb2901fcfc20] ksys_write at ffffffff9724a1df
 #8 [ffffbb2901fcfc58] do_syscall_64 at ffffffff97acd45c
 #9 [ffffbb2901fcff50] entry_SYSCALL_64_after_hwframe at ffffffff97c00130
    RIP: 00007fec1a93eb47  RSP: 00007ffe39fbc638  RFLAGS: 00000246
    RAX: ffffffffffffffda  RBX: 0000000000000002  RCX: 00007fec1a93eb47
    RDX: 0000000000000002  RSI: 0000562e5aad0300  RDI: 0000000000000001
    RBP: 0000562e5aad0300   R8: 0000000000000000   R9: 00007fec1a9b14e0
    R10: 00007fec1a9b13e0  R11: 0000000000000246  R12: 0000000000000002
    R13: 00007fec1a9fb780  R14: 0000000000000002  R15: 00007fec1a9f69e0
    ORIG_RAX: 0000000000000001  CS: 0033  SS: 002b
```

V backtrace pro úlohu s `PID 3582` lze vidět, že se snaží zamknout mutex pomocí funkce `mutex_lock`. Funkce `schedule` naznačují čekání na odemčení mutexu.

### Processes
```bash
crash> ps 3582
      PID    PPID  CPU       TASK        ST  %MEM      VSZ      RSS  COMM
     3582    3445   1  ffff9a20c53aa300  UN   0.1     9220     6276  bash

crash> ps 1
      PID    PPID  CPU       TASK        ST  %MEM      VSZ      RSS  COMM
        1       0   0  ffff9a20c0264600  UN   0.2   108244    18088  systemd

```

Procesy s `PID 3582` a `PID 1` jsou ve stavu `UNINTERRUPTIBLE`.

### mmap_lock
Nyní je třeba prověřit, zda proces `PID 3582` opravdu uzamčel zámek pro `PID 1`.

Adresy struktur `task_struct`, které obsahují veškeré informace o daných úlohách, lze využít s následujícími příkazy pro zisk adresy zámku:

```bash
crash> task_struct ffff9a20c0264600 | grep mm
  mm = 0xffff9a20c0063200
```
Tímto byla získána adresa struktury `mm_struct = 0xffff9a20c0063200`, která reprezentuje deskriptor paměti procesu. To znamená, že nese informace o jeho virtuální paměti a hlavně obsahuje synchronizační primitivum (semafor pro čtení/zápis) `mmap_lock` typu `rw_semaphore`.

```bash
crash> mm_struct.mmap_lock 0xffff9a20c0063200 -o
struct mm_struct {
  [ffff9a20c0063270]     struct rw_semaphore mmap_lock;
}
```

Adresa semaforu `rw_semaphore mmap_lock` je **`ffff9a20c0063270`**.

```bash
crash> whatis struct rw_semaphore
struct rw_semaphore {
    atomic_long_t count;
    atomic_long_t owner;
    struct optimistic_spin_queue osq;
    raw_spinlock_t wait_lock;
    struct list_head wait_list;
}
```

Struktura `rw_semaphore` sdílí s již výše zmíněnou strukturou `mutex` hodně atributů, aktuálně nejzamavějším je atribut `owner`, který obsahuje `ID` procesu, který **aktuálně** vlastní mutex (semafor), vysvětleno výše u popisu `struct mutex`.

```bash
crash> rw_semaphore ffff9a20c0063270
struct rw_semaphore {
  count = {
    counter = 0x3
  },
  owner = {
    counter = 0xffff9a20c53aa300
  },
  osq = {
    tail = {
      counter = 0x0
    }
  },
  wait_lock = {
    raw_lock = {
      {
        val = {
          counter = 0x0
        },
        {
          locked = 0x0,
          pending = 0x0
        },
        {
          locked_pending = 0x0,
          tail = 0x0
        }
      }
    }
  },
  wait_list = {
    next = 0xffffbb2900013e50,
    prev = 0xffffbb2900cff970
  }
}
```

Adresy atributu owner a adresa task_struct pro PID 3582 se shodují: **`0xffff9a20c53aa300 = 0xffff9a20c53aa300`**

Nyní je už jasné, že proces s `PID 3582` skutečně zamknul mutex/semafor procesu s `PID 1`.   

Pokud se všechny zmíněné kroky provedou i nad adresou task_struct (`0xffff9a20c53aa300`) pro proces `PID 3582`, tak v atributu `owner` je adresa **`0xffff9a20c53aa301`**, která se liší pouze v nejnizším bitu a to z toho důvodu, že slouží jako příznak pro to, že je zámek **držen** pro zápis, tzn. že ostatní procesy musí čekat.

### Příčina paniky jádra
Panika jádra nastala v důsledku uváznutí, při přístupu ke zdrojům s výlučným přístupem (**deadlock**), u procesů `PID 3582` (viník) a `PID 1`.

Na základě nasbíraných a analyzovaných informací je rekonstrukce paniky následující:
- do jádra se načetl modul `smajdalf`, včetně registrace handler funkce `take_the_lock_of_power`
- handler funkce byla aktivována (pravděpodobně výpis "*Smajdalf: Carodej nikdy nechodi pozde.*")
- Podle kódu funkce handleru nejprve probíhal spin-loop, poté se dvakrát po sobě volá funkce `mutex_lock`, která při prvním volání uzamče mutex a po druhém zablokuje vlastní proces `PID 3582`
- Proces `systemd` s `PID 1` se snaží přistoupit k semaforu, který byl právě zablokován a čeká na jeho uvolnění - zřejmé z backtrace (`down_read`, `rwsem_down_read_slowpath`, `schedule_preempt_disabled`)
- Po uplynutí více jak 120 sekund (`122 s`) je problém detekován mechanismy `khungtaskd` a `watchdog`
- Jelikož byl `sysctl_hung_task_panic` nastaven na 1, jádro vyvolalo paniku.


### Možné řešení
- Nepoužívat modul
- Úprava modulu `smajdalf` - vyřešení problému, kde se mutex_lock volá dvakrát po sobě, případně zajištění odemykání mutexu
- Přeskočení kódu, kde nastane uváznutí na základě podmínek ve funkci
- Vypnutí `sysctl_hung_task_panic`

## Závěr
Na projektu jsem strávil dohromady kolem 15 hodin, primárně kvůli studiu dokumentace kernelu.

## Zdroje

The Linux Foundation. (n.d.). Kernel documentation. Dostupné z: https://docs.kernel.org/ [cit. 8. dubna 2025].