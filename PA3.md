## PA3-穿越时空的旅程：异常控制流 实验报告

### 一、加载程序与系统调用

PA2我们完成的AM: abstract machine，裸机，是计算机的抽象模型。

AM=TRM图灵机+IOE输入输出扩展+ASYE异步处理扩展+PTE保护扩展+MPE多处理器扩展

PA3要求我们实现nanos-lite操作系统

nemu是x86模拟器，nanos-lite是nemu的客户程序，仙剑运行在nanos-lite之上

用户程序位于navy-apps，通过loader函数加载程序

#### 1.加载操作系统的第一个用户程序dummy

首先修改navy-apps/Makefile.check，让navy-apps项目上的程序默认编译到 x86 中：

```makefile
ISA ?= x86
```

在navy-apps/tests/dummy下执行make，生成dummy的可执行文件dummy-x86。

之后在nanos-lite下执行make update生成ramdisk.img镜像文件（将特定的一系列文件按照一定的格式制作成单一的文件），里面就是需要加载的用户程序。之后通过make run命令，loader加载器会对这个img镜像文件进行加载。

但是，执行后会发生错误：无法创建符号链接

![无法创建符号链接](C:\Users\Mika\Desktop\综合课程设计\pa3pic\无法创建符号链接.png)

这实际上是由于在windows共享文件夹下，没法跨文件系统创建到linux本地目录的链接，所以只要将文件夹移动到linux的目录下（如/下载），再make update即可。（注意要重新修改环境变量！）

```makefile
export NEMU_HOME=~/下载/ics2018/nemu
export AM_HOME=~/下载/ics2018/nexus-am
export NAVY_HOME=~/下载/ics2018/navy-apps
```

##### 实现loader加载器

loader位于nanos-lite/src/loader.c中

loader将ramdisk（我们用内存模拟的磁盘）中从0开始的所有内容放置在0x4000000，并把这个地址作为程序的入口返回，执行用户程序

```c
#define DEFAULT_ENTRY ((void *)0x4000000)
extern uint8_t ramdisk_start,ramdisk_end;
#define RAMDISK_SIZE ((&ramdisk_end)-(&ramdisk_start))
extern void ramdisk_read(void *buf, off_t offset, size_t len);

//loader加载器：将 ramdisk 中从 0 开始的所有内容放置在 0x4000000，并把这个地址作为程序的入口返回
uintptr_t loader(_Protect *as, const char *filename) {
  //TODO();
  ramdisk_read(DEFAULT_ENTRY,0,RAMDISK_SIZE);
  return (uintptr_t)DEFAULT_ENTRY;
}
```

##### 踩坑1

之后遇到了一个小问题，竟然卡了我一周。。。就是在nanos-lite每次make run的时候都会出现缺少宏定义SYSCALL_ARG1的错误：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\syscall error.png" alt="syscall error" style="zoom:80%;" />

这其实是因为每个头文件（比如am.h）在native文件夹里和x86-nemu文件夹里都有一份，默认使用的是native文件夹里的头文件，可以看到第一行显示：Building nanos-lite [native]，而那里的代码是不完整的，所以肯定编译失败。



于是我尝试在整个目录中查找字符串：`grep -r x86-nemu`，立马知道了答案（不得不说`grep -r` 命令实在是太好用了）：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\x86-nemu.png" alt="x86-nemu" style="zoom:80%;" />

:star:刚才我们将navy-apps项目上的程序默认编译到 x86 中，所以此时需要使用`make ARCH=x86-nemu run`来编译。

这样一来，就可以看到下面第一行的Building nanos-lite [x86-nemu]了！

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\makerun0.png" alt="makerun0" style="zoom:80%;" />

然后运行nemu，出现了pa2里经常看到的界面：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\make_run.png" alt="make_run" style="zoom: 80%;" />

使用`objdump -S dummy-x86`查看dummy-x86的反汇编程序，可以看到4001f98处还没有被实现的指令为int $0x80，该指令用来产生系统调用的异常，在下文中会详细说明。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\4001f98.png" alt="4001f98"  />



#### 2.等级森严的制度——特权级

i386有四个特权级ring0~ring3，0最高，3最低，一般只用0和3两个特权级。操作系统特权级为0，用户进程特权级为3，但为了方便，nemu中的用户进程都运行在ring0。

i386有三个特权级相关属性：DPL：数据所在的特权级；RPL：请求者所在的特权级；CPL：当前进程的特权级。只有当DPL>=RPL&&DPL>=CPL，数据的访问才是合法的。

对于低特权级向高特权级数据访问的检查是通过硬件门电路来实现的。

#### 3.操作系统的义务——系统调用

操作系统有最高特权级，相应的义务是管理系统中所有资源，为用户进程提供服务。比如操作系统为了安全不能允许用户进程直接使用io设备，需要让用户进程向os合法申请，即系统调用。

用户进程将系统调用的参数放入通用寄存器，然后通过int $0x80指令触发一个系统调用的异常，操作系统能够识别并进入内核态。

navy-apps/libs/libos/src/nanos.c中显示了系统调用的接口：

```c
int _syscall_(int type, uintptr_t a0, uintptr_t a1, uintptr_t a2){
  int ret = -1;
  asm volatile("int $0x80": "=a"(ret): "a"(type), "b"(a0), "c"(a1), "d"(a2));
  return ret;
}
```

\_syscall_产生一个系统调用的异常：首先把参数放入四个寄存器eax~edx，然后执行int $0x80指令，最后从eax获得系统调用的返回值

#### 4.穿越时空的旅程——中断处理

CPU监测到中断后，会根据一个结构体——门描述符跳转到一个目标地址。

i386将一段内存作为**中段描述符表（IDT）**，里面存储异常号-门描述符的映射，异常号由**int指令**或者CPU内部给出。

i386通过**lidt指令**在**IDTR寄存器**中设置IDT的始址和长度。这样，一旦发生异常，就通过IDTR->IDT->门描述符->目标地址进行跳转。

而在这之前，为了中断处理完成后能够返回原地址，首先需要int指令将eflags,cs,eip的值压栈。

#### 5.准备IDT

注意：首先需要开启nanos-lite/src/main.c中的HAS_ASYE宏定义，这样才能打开ASYE异步处理扩展，从而可以调用_asye_init函数。



初始化IDT：nexus-am\am\arch\x86-nemu\src\asye.c的_asye_init函数。

首先填好中断描述符表，即每个异常与门描述符的映射，然后单独设定系统调用的中断，最后通过set_idt函数设定IDT的首地址和长度。

```c
void _asye_init(_RegSet*(*h)(_Event, _RegSet*)) {
  // initialize IDT
  for (unsigned int i = 0; i < NR_IRQ; i ++) {
    idt[i] = GATE(STS_TG32, KSEL(SEG_KCODE), vecnull, DPL_KERN);
  }

  // -------------------- system call --------------------------
  idt[0x80] = GATE(STS_TG32, KSEL(SEG_KCODE), vecsys, DPL_USER);

  set_idt(idt, sizeof(idt));

  // register event handler
  H = h;
}
```

set_idt：nexus-am\am\arch\x86-nemu\include\x86.h。

使用data数组来存储idt的首地址和长度，之后调用lidt指令将data的信息存入IDTR寄存器。

```c
static inline void set_idt(GateDesc *idt, int size) {
  volatile static uint16_t data[3];
  data[0] = size - 1;
  data[1] = (uint32_t)idt;
  data[2] = (uint32_t)idt >> 16;
  asm volatile("lidt (%0)" : : "r"(data));
}
```
在nemu/include/cpu/reg.h中定义IDTR寄存器的结构
```c
//IDTR寄存器，存储中断描述符表idt的首地址和长度
	struct IDTR{
	  uint32_t base;
	  uint16_t limit;
	}idtr;
} CPU_state;
```
此时再make run，首先发现缺少lidt指令。

##### lidt指令：在IDTR寄存器中设置IDT的始址和长度

在data的首地址被送到eax后，译码函数将读取eax中的数据，写入id_dest

执行函数从id_dest中读出IDT的长度和首地址，并写入idtr寄存器

```c
make_DHelper(lidt_a){
  decode_op_a(eip,id_dest,true);
}

make_EHelper(lidt) {
  //TODO();
  t1=id_dest->val;//address of data array
  rtl_lm(&t0,&t1,2);//t0 = data[0], the limit length of IDT
  cpu.idtr.limit=t0;

  t1=id_dest->val+2;
  rtl_lm(&t0,&t1,4);//t0 = base address of IDT, 32bit
  cpu.idtr.base=t0;

  print_asm_template1(lidt);
}
```
#### 6.触发异常

##### int指令：触发异常并跳转到中断处理程序的地址

首先在reg.h中为cpu增加cs寄存器，cs是为了内存分段机制，虽然nemu没有采用，但为了int指令的完整就在此定义。

在monitor.c的restart函数中，初始化cs寄存器=8

```c
	rtlreg_t cs;
} CPU_state;

cpu.cs=8;//初始化cs
```
intr.c中的raise_intr是int执行函数的主要内容，包括以下步骤：

- 将eflags,cs,eip的值压栈
- 从IDTR读出IDT的长度和首地址cpu.idtr.base
- 在IDT中找到中断号NO对应的门描述符首地址gate_addr
- 根据门描述符的offset计算目标地址，由两部分拼接而成
- 跳转到目标地址target_addr

```c
//处理中断，输入中断号，返回地址
void raise_intr(uint8_t NO, vaddr_t ret_addr) {
  /* TODO: Trigger an interrupt/exception with ``NO''.
   * That is, use ``NO'' to index the IDT.
   */

  //TODO();
  memcpy(&t1,&cpu.eflags,sizeof(cpu.eflags));
  rtl_li(&t0,t1);
  rtl_push(&t0);//eflags
  rtl_push(&cpu.cs);//cs
  rtl_li(&t0,ret_addr);
  rtl_push(&t0);//eip

  //在IDT中找到中断号NO对应的门描述符首地址
  vaddr_t gate_addr=cpu.idtr.base+NO*sizeof(GateDesc);
  Log("gate_addr=%d, cpu.idtr.base=%d, cpu.idtr.limit=%d",gate_addr,cpu.idtr.base,cpu.idtr.limit);
  assert(gate_addr<=cpu.idtr.base+cpu.idtr.limit);//通过

  //根据门描述符的offset计算目标地址，由两部分拼接而成
  uint32_t off_15_0=vaddr_read(gate_addr,2);
  uint32_t off_32_16=vaddr_read(gate_addr+sizeof(GateDesc)-2,2);
  uint32_t target_addr=(off_32_16<<16)+off_15_0;

  decoding.is_jmp=1;
  decoding.jmp_eip=target_addr;
}
```
在system.c中实现int的执行函数：调用raise_intr，参数为中断号和返回地址（即当前指令的下一条指令地址）
```c
extern void raise_intr(uint8_t NO,vaddr_t ret_addr);

make_EHelper(int) {
  //TODO();
  uint8_t NO=id_dest->val&0xff;//低8bit
  raise_intr(NO,decoding.seq_eip);//返回地址是下一条指令seq_eip

  print_asm("int %s", id_dest->str);

#ifdef DIFF_TEST
  diff_test_skip_nemu();
#endif
}
```

然后make run，发现缺少pusha指令

#### 7.保存现场

触发中断后，就需要进行中断处理，这必须要使用通用寄存器。但当前通用寄存器中存放的是中断前的内容，不可以被覆盖，所以需要使用pusha指令将通用寄存器的值压入堆栈。

我们之前在_asye_init中看到，系统调用会调用入口函数vecsys

```c
// -------------------- system call --------------------------
idt[0x80] = GATE(STS_TG32, KSEL(SEG_KCODE), vecsys, DPL_USER);
```

在nexum-am/am/arch/x86-nemu/src/trap.S汇编程序中可以看到vecsys会跳转到asm_trap

```assembly
#----|-------entry-------|-errorcode-|---irq id---|---handler---|
.globl vecsys;    vecsys:  pushl $0;  pushl $0x80; jmp asm_trap
.globl vecnull;  vecnull:  pushl $0;  pushl   $-1; jmp asm_trap

asm_trap:
  pushal

  pushl %esp
  call irq_handle

  addl $4, %esp

  popal
  addl $8, %esp

  iret
```

asm_trap会将通用寄存器的内容以及错误码errror code，异常号irq（就是上面说的中断号NO），eflags，cs，eip会打包成一个数据结构，称为**trap frame（陷阱帧）**。trap frame完整地记录了中断发生时的状态，依靠它来恢复现场。然后用pusha（pushal）指令把trap frame压栈。

##### pusha指令
执行函数在data-mov.c中，按照压栈的顺序实现
```c
make_EHelper(pusha) {
  //TODO();
  t0 = cpu.esp;
  rtl_push(&cpu.eax);
  rtl_push(&cpu.ecx);
  rtl_push(&cpu.edx);
  rtl_push(&cpu.ebx);
  rtl_push(&t0);
  rtl_push(&cpu.ebp);
  rtl_push(&cpu.esi);
  rtl_push(&cpu.edi);
  print_asm("pusha");
}
```

##### trap frame的结构

接下来重新组织nexus-am/am/arch/x86-nemu/include/arch.h中的_RegSet结构体，这就是完整的trapframe的结构，各种寄存器定义的顺序就是压栈的相反顺序，最后压栈的作为trapframe的头部。

```c
struct _RegSet {
  uintptr_t edi,esi,ebp,esp,ebx,edx,ecx,eax;
  int       irq;
  uintptr_t error_code,eip,cs,eflags;
};
```

之后进行make run，会触发一个bad trap。

![after pusha](C:\Users\Mika\Desktop\综合课程设计\pa3pic\after pusha.png)



##### 对比异常和函数调用

函数调用发生的时间是已知的，而异常发生的时间是未知的；函数调用是为主程序服务的，而异常与主程序之间没有关系。



##### trap.S中pushl %esp的作用

```assembly
  pushl %esp
  call irq_handle
```
首先，每次压栈的过程中，esp都会自减，指向新的栈顶。

函数调用时，先将参数压栈，然后将eip的值（返回地址）压栈。进入函数后，先将ebp（之前的栈底位置）压栈，再将当前esp的值赋给ebp，这样ebp就指向了新的栈底。

trap.S中pushl %esp的esp是作为irq_handle函数的参数被压栈的，目的是将trap frame的首地址作为参数传给irq_handle函数。

#### 8.事件分发

使用trap frame保存现场之后，调用irq_handle（nexus-am\am\arch\x86-nemu\src\asye.c）**把异常封装为事件**ev.event，根据异常号irq进行分发（其实就是处理不同情况）。

然后调用nanos-lite\src\irq.c中的do_event函数来再次分发事件。do_event是在init_irq中调用的，而init_irq则在main.c中调用

```c
_RegSet* irq_handle(_RegSet *tf) {
  _RegSet *next = tf;
  if (H) {
    _Event ev;
    switch (tf->irq) {
      case 0x80: ev.event = _EVENT_SYSCALL; break;
      default: ev.event = _EVENT_ERROR; break;
    }

    next = H(ev, tf);
    if (next == NULL) {
      next = tf;
    }
  }

  return next;
}

static _RegSet* do_event(_Event e, _RegSet* r) {
  switch (e.event) {
    default: panic("Unhandled event ID = %d", e.event);
  }

  return NULL;
}
```

对于当前的系统调用事件，会使用nanos-lite/src/syscall.c中的do_syscall进行处理。

```c
_RegSet* do_syscall(_RegSet *r) {
  uintptr_t a[4];
  a[0] = SYSCALL_ARG1(r);

  switch (a[0]) {
    default: panic("Unhandled syscall ID = %d", a[0]);
  }

  return NULL;
}
```
修改刚才的do_event函数，一旦发生系统调用，就执行do_syscall，这是二次分发的过程
```c
extern _RegSet* do_syscall(_RegSet *r);
static _RegSet* do_event(_Event e, _RegSet* r) {
  switch (e.event) {
  	case(_EVENT_SYSCALL):
  	  return do_syscall(r);
    default: panic("Unhandled event ID = %d", e.event);
  }

  return NULL;
}
```

此时make run，就会出现一个系统调用的panic，表示系统调用号为0的系统调用没有被处理。

![syscall](C:\Users\Mika\Desktop\综合课程设计\pa3pic\syscall.png)

#### 9.系统调用处理

do_syscall通过SYSCALL_ARG1从保存的现场r中获得系统调用参数，四个参数位于eax,ebx,ecx,edx，通过其中第一个参数系统调用号进行处理。

首先修改nexus-am/am/arch/x86-nemu/include/arch.h中的宏定义，从现场r中正确的寄存器取参数

```c
#define SYSCALL_ARG1(r) r->eax
#define SYSCALL_ARG2(r) r->ebx
#define SYSCALL_ARG3(r) r->ecx
#define SYSCALL_ARG4(r) r->edx
```

然后修改系统调用处理函数do_syscall，定义0号系统调用SYS_none的处理方法sys_none函数，并用SYSCALL_ARG1(r)记录返回值。

```c
int sys_none(){
  return 1;
}

_RegSet* do_syscall(_RegSet *r) {
  uintptr_t a[4];
  a[0] = SYSCALL_ARG1(r);
  a[1] = SYSCALL_ARG2(r);
  a[2] = SYSCALL_ARG3(r);
  a[3] = SYSCALL_ARG4(r);

  switch (a[0]) {
    case SYS_none:SYSCALL_ARG1(r)=sys_none();break;
    default: panic("Unhandled syscall ID = %d", a[0]);
  }

  return NULL;
}
```

然后make run，会发现需要实现popa和iret指令。

#### 10.恢复现场

系统调用处理完成后，将会回到asm_trap中，根据之前保存的trap frame，恢复用户进程的现场，一些不需要的信息会直接pop出去，最后执行iret指令，从异常处理中返回。

```assembly
asm_trap:
  pushal

  pushl %esp
  call irq_handle

  addl $4, %esp

  popal
  addl $8, %esp

  iret
```

##### popa

弹栈与pusha压栈的顺序完全相反

```c
make_EHelper(popa) {
  //TODO();
  rtl_pop(&cpu.edi);
  rtl_pop(&cpu.esi);
  rtl_pop(&cpu.ebp);
  rtl_pop(&t0);
  rtl_pop(&cpu.ebx);
  rtl_pop(&cpu.edx);
  rtl_pop(&cpu.ecx);
  rtl_pop(&cpu.eax);
  print_asm("popa");
}
```

##### iret

iret指令将栈顶的三个元素来依次解释成 EIP,CS,EFL，并恢复它们。

```c
//中断返回
make_EHelper(iret) {
  //TODO();
  rtl_pop(&cpu.eip);
  rtl_pop(&cpu.cs);
  rtl_pop(&t0);
  memcpy(&cpu.eflags,&t0,sizeof(cpu.eflags));

  decoding.jmp_eip=1;
  decoding.seq_eip=cpu.eip;

  print_asm("iret");
}
```
此时make run，会发现缺少4号系统调用的处理函数。

![syscall4](C:\Users\Mika\Desktop\综合课程设计\pa3pic\syscall4.png)

参考syscall.h可以知道，需要实现的是sys_exit函数，接收一个退出状态的参数，用这个参数调用_halt()即可。那么怎么知道do_syscall里面的sys_exit填第几个参数呢？其实因为a[0]已经用来作为系统调用号，又因为sys_exit只有一个参数，所以按顺序选择a[1]就可以了。
```c
void sys_exit(int a){
  _halt(a);
}

_RegSet* do_syscall(_RegSet *r) {
  uintptr_t a[4];
  a[0] = SYSCALL_ARG1(r);
  a[1] = SYSCALL_ARG2(r);
  a[2] = SYSCALL_ARG3(r);
  a[3] = SYSCALL_ARG4(r);

  switch (a[0]) {
    case SYS_none:SYSCALL_ARG1(r)=sys_none();break;
    case SYS_exit:sys_exit(a[1]);break;
    default: panic("Unhandled syscall ID = %d", a[0]);
  }

  return NULL;
}

```

最后，再次执行make run，可以看到hit good trap，阶段一到此结束。

![stage1fin](C:\Users\Mika\Desktop\综合课程设计\pa3pic\stage1fin.png)

---

### 二、堆区管理和文件系统

阶段二需要实现各种系统调用，在nanos-lite/src/syscall.c里的do_syscall中添加各种情况，并编写sys_xx函数来处理系统调用，最后设置系统调用的返回值，并放入SYSCALL_ARG1(r)中。

#### 1.输出helloworld

首先需要将待运行的程序从dummy换成hello，先在tests/hello下make，然后将nanos-lite的makefile中dummy换成hello，最后make update。

##### sys_write

_putc函数（nexus-am\am\arch\x86-nemu\src\trm.c）将字符ch输出到串口

```c
void _putc(char ch) {
#ifdef HAS_SERIAL
  while ((inb(SERIAL_PORT + 5) & 0x20) == 0);
  outb(SERIAL_PORT, ch);
#endif
}
```

通过`man 2 write`命令，可以知道write系统调用的参数格式和返回值等信息。

sys_write有三个参数，和之前说的sys_exit类似，case里面也要按顺序写这些参数对应的a[i]。如果输出成功，返回字节数，否则返回-1.

```c
//fd是文件描述符，将要把buf中的len字节输出
int sys_write(int fd,void *buf,size_t len){
  if(fd==1||fd==2){
    char c;
    for(int i=0;i<len;++i){
      memcpy(&c,buf+i,1);
      _putc(c);
    }
    return len;
  }
  else panic("Unhandled fd=%d in sys_write",fd);
  return -1;
}

case SYS_write:SYSCALL_ARG1(r)=sys_write(a[1],(void*)a[2],a[3]);break;

```

此外，还要在navy-apps/libs/libos/src/nanos.c中实现调用系统调用接口函数_write()

```c
int _write(int fd, void *buf, size_t count){
  return _syscall_(SYS_write,fd,(uintptr_t)buf,count);
  //_exit(SYS_write);
}
```

make run，这样就成功运行了hello程序，不断将hello world输出到串口。

![helloworld](C:\Users\Mika\Desktop\综合课程设计\pa3pic\helloworld.png)

#### 2.堆区管理

前面的输出是逐个字节调用write输出的，因为第一次使用printf时malloc申请缓冲区失败。malloc和free库函数用来在用户程序的堆区申请或释放一块内存。

也就是说printf内部会调用malloc，而malloc内部会调用sbrk：

sbrk (increment) 库函数用于将用户程序的数据段结束的位置（program break）增长increment字节，increment可以为负数，这就可以调整堆区大小。可执行文件里面有代码段和数据段，链接的时候 ld（链接器） 会默认添加一个名为\_end 的符号指示数据段结束的位置。

用户程序开始运行时，program break位于_end指示的位置，意味着此时堆区的大小为0。之后可以调用sbrk来动态调整program break的位置，这样当前位置和初始位置之间的区域就可以作为用户程序的堆区。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\内存分段.png" alt="内存分段" style="zoom:67%;" />

从上面的内存分段图中可以看出，数据段包含初始化为非零的数据区、BSS和堆三个区域。初始化非零数据区域一般存放静态非零数据和全局的非零数据；BSS主要存放未初始化的全局数据和静态数据；剩下的就是堆了，用sbrk来动态分配内存。

##### sys_brk：调整堆区大小，动态分配内存

sys_brk（system.c）：

定义系统调用sys_brk，目前Nanos-lite 还是一个单任务操作系统，空闲的内存都可以让用户程序自由使用，因此我们只需要让 SYS_brk 系统调用总是返回 0 即可，表示堆区大小的调整总是成功。


```c
//addr是新的program break位置
int sys_brk(int addr){
  return 0;
}

case SYS_brk:SYSCALL_ARG1(r)=sys_brk(a[1]);break;
```
_sbrk（nanos.c）：

malloc内部的sbrk会调用\_sbrk函数，由该函数通过\_syscall_来引发系统调用。

具体的步骤是：首先设置静态变量probreak（pb）并将其初始化为end，此时堆区的大小为0。然后申请系统调用，如果堆可以增长，那么更新pb的位置为probreak+increment，并将pb的旧值返回；否则返回-1表示分配失败。

之前该函数只能返回-1，所以无法分配堆空间，程序只能逐个字节调用write输出。

```c
//希望数据段结束地址改变increment字节，来分配堆区
void *_sbrk(intptr_t increment){
  extern char end;
  static uintptr_t probreak=(uintptr_t)&end;//初始化pb
  uintptr_t probreak_new=probreak+increment;
  int r=_syscall_(SYS_brk,probreak_new,0,0);//系统调用
  if(r==0){//分配成功
    uintptr_t temp=probreak;//旧的pb位置
    probreak=probreak_new;//更新pb
    return (void*)temp;
  }
  return (void *)-1;//分配失败
}
```

##### 踩坑2

需要注意的是，每次修改nanos.c里的函数，都需要重新编译c程序，然后在nanos-lite目录下make update，要不然相当于没修改，在这卡了一段时间qwq

在sys_write里面加入Log("qwq");后再make run，可以看到添加sys_brk系统调用前后输出方式的变化：

之前：字符逐个输出

![before_sysbrk](C:\Users\Mika\Desktop\综合课程设计\pa3pic\before_sysbrk.png)

之后：整条文本都进入动态分配内存后的缓冲区，一起输出

![after_sysbrk](C:\Users\Mika\Desktop\综合课程设计\pa3pic\after_sysbrk.png)

#### 3.简易文件系统

虽然操作系统Nanos-lite已经可以通过ramdisk的读写接口来访问文件，但我们希望用户程序也能够知道每个文件位于磁盘的位置，而不使用操作系统的接口，因此需要实现文件系统进行文件到磁盘地址映射的管理。

将navy-apps/fsimg/目录下的所有内容整合成ramdisk镜像，会生成一个**文件记录表**，记录ramdisk中各个文件的信息。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\文件记录表.png" alt="文件记录表" style="zoom:80%;" />

在fs.c中可以看到文件记录表Finfo的结构：包含文件名，大小以及硬盘上的偏移量

```c
typedef struct {
  char *name;
  size_t size;
  off_t disk_offset;
  off_t open_offset;//读写指针
} Finfo;
```

为了方便管理文件，操作系统使用**文件描述符**fd来表示一个打开的文件，并维护fd到具体文件的映射。这样，系统调用open通过文件名打开文件，而返回fd，从而read和write就通过fd来对文件操作。

另外，还需要在文件记录表里添加一个读写指针open_offset（单位是字节），记录目前文件操作的位置，这样不用每次都从头开始读写文件。

##### fs_open, fs_read, fs_write, fs_close, fs_lseek

现在我们需要在fs.c中实现文件管理相关的函数，包括文件的打开、关闭、读、写、移动读写指针。

最好在每个函数中都用`assert(fd>=0&&fd<NR_FILES);`来避免fd取值越界。

首先为方便定义一些工具函数：

```c
//文件总数
#define NR_FILES (sizeof(file_table) / sizeof(file_table[0]))

extern void ramdisk_read(void *buf,off_t offset,size_t len);
extern void ramdisk_write(void *buf,off_t offset,size_t len);

//返回文件大小
size_t fs_filesz(int fd){
  assert(fd>=0&&fd<NR_FILES);
  return file_table[fd].size;
}

//磁盘偏移
off_t disk_offset(int fd){
  assert(fd>=0&&fd<NR_FILES);
  return file_table[fd].disk_offset;
}

//读写指针
off_t get_open_offset(int fd){
  assert(fd>=0&&fd<NR_FILES);
  return file_table[fd].open_offset;
}

//将读写偏移指针设置为n
void set_open_offset(int fd,int n){
  assert(fd>=0&&fd<NR_FILES);
  assert(n>=0);
  if(n>file_table[fd].size){
    n=file_table[fd].size;
  }
  file_table[fd].open_offset=n;
}
```

fs_open：通过比较字符串在文件记录表里查找对应的项，返回文件描述符fd。

fs_close：由于我们的简易文件系统没有维护文件打开的状态，fs_close()可以直接返回 0,表示总是关闭成功。

```c
//打开文件，返回文件标识符
int fs_open(const char *filename,int flags,int mode){
  for(int i=0;i<NR_FILES;++i){
    if(strcmp(filename,file_table[i].name)==0){
      return i;
    }
  }
  panic("file not exist in file_table!");
  return -1;
}

int fs_close(int fd){
  assert(fd>=0&&fd<NR_FILES);
  return 0;
}
```

fs_read，fs_write：

需要注意的是，要读写的长度len可能超过当前读写指针到文件末尾的长度，所以要取它们的最小值作为真正读写的长度。

还有一点，fd=0,1,2分别对应标准输入 stdin，标准输出 stdout 和标准错误stderr，这三种fd暂时不去考虑。

```c
//从fd文件的offset处开始，读最多len个字节到buf中，返回实际字节数
ssize_t fs_read(int fd,void *buf,size_t len){
  assert(fd>=0&&fd<NR_FILES);
  if(fd<3){//stdout或stderr
    return 0;
  }
  int n=fs_filesz(fd)-get_open_offset(fd);//当前文件剩余长度
  if(n>len){
    n=len;//实际读取的长度不能超过n
  }
  //从文件当前的位置读len个字节到buf
  ramdisk_read(buf,disk_offset(fd)+get_open_offset(fd),n);
  //更新偏移量
  set_open_offset(fd,get_open_offset(fd)+n);
  return n;
}

//buf写入文件
ssize_t fs_write(int fd,void *buf,size_t len){
  assert(fd>=0&&fd<NR_FILES);
  if(fd<3){//写入stdout或stderr
    return 0;
  }
  int n=fs_filesz(fd)-get_open_offset(fd);//当前文件剩余长度
  if(n>len){
    n=len;//实际读取的长度不能超过n
  }
  ramdisk_write(buf,disk_offset(fd)+get_open_offset(fd),n);
  //更新偏移量
  set_open_offset(fd,get_open_offset(fd)+n);
  return n;
}
```
fs_lseek：根据whence不同，将读写偏移指针移动到某处

其中有三种情况：开始位置+offset，当前位置+offset，文件末尾

```c
//根据whence不同，将读写偏移指针移动到某处
off_t fs_lseek(int fd,off_t offset,int whence){
  switch(whence){
    case SEEK_SET://开始位置+offset
      set_open_offset(fd,offset);
      return get_open_offset(fd);
    case SEEK_CUR://当前位置+offset
      set_open_offset(fd,get_open_offset(fd)+offset);
      return get_open_offset(fd);
    case SEEK_END://末尾
      set_open_offset(fd,fs_filesz(fd)+offset);
      return get_open_offset(fd);
    default:
      panic("Unhandled whence ID = %d",whence);
      return -1;
  }
}
```



之后在syscall.c中需要定义响应的系统调用函数，以sys_read为例：

```c
int sys_read(int fd,void *buf,size_t len){
  return fs_read(fd,buf,len);
}
```
在nanos.c定义用户程序使用的系统调用的接口函数，以_read为例：
```c
int _read(int fd, void *buf, size_t count) {
  return _syscall_(SYS_read,fd,(uintptr_t)buf,count);
  //_exit(SYS_read);
}
```


##### 新的loader

在loader.c中，需要修改之前的loader函数。之前loader加载程序时，ramdisk上只有一个文件，所以直接调用ramdisk_read来加载用户程序。

当文件数量增加后，需要使用刚才编写的文件管理函数来完成加载。首先通过文件名找到对应的文件描述符fd，之后把文件整个读入内存DEFAULT_ENTRY处，最后关闭文件，这就是整个加载过程。

```c
uintptr_t loader(_Protect *as, const char *filename) {
  //TODO();
  //ramdisk_read(DEFAULT_ENTRY,0,RAMDISK_SIZE);//PA3.1
  int fd=fs_open(filename,0,0);
  Log("filename=%s,fd=%d",filename,fd);
  fs_read(fd,DEFAULT_ENTRY,fs_filesz(fd));//把文件整个读入内存DEFAULT_ENTRY处
  fs_close(fd);
  return (uintptr_t)DEFAULT_ENTRY;
}

```

最后在main.c中，修改loader的参数，此时我们只需填写要加载的文件名，就可以加载了。

```c
uint32_t entry = loader(NULL, "/bin/text");//加载用户程序
```

最后千万别忘了make update一下，然后make run，就可以看到PASS!!!了：

![pa3.2pass](C:\Users\Mika\Desktop\综合课程设计\pa3pic\pa3.2pass.png)

至此，PA3第二阶段完成！

---

### 三、一切皆文件

因为不同设备的不同功能纷繁复杂，不可能全部都单独提供一个系统调用，因此需要**把IOE抽象成文件**，即用文件来表示各种IOE的信息，这样只需要使用阶段二所完成的对文件的接口就可以操作所有设备了。

#### 1.把VGA抽象成文件

VGA(Video Graphics Array)是视频图形阵列，现在我们要把视频信息输出到屏幕上了。

显存：显卡内存，用来存储要处理的图形信息，抽象成文件/dev/fb，需要支持写操作和lseek，以便于用户程序把像素更新到屏幕的指定位置上

屏幕大小的信息通过/proc/dispinfo文件来获得，需要支持读操作



首先在fs.c中init_fs对显存/dev/fb大小初始化，通过getScreen函数获得屏幕宽高，并计算出屏幕大小，注意每个像素是4字节。
```c
//对显存大小初始化
void init_fs() {
  // TODO: initialize the size of /dev/fb
  extern void getScreen(int *width,int *height);
  int width=0,height=0;
  getScreen(&width,&height);//获取屏幕宽高
  //FD_FB是显存的文件描述符
  file_table[FD_FB].size=width*height*sizeof(uint32_t);//每个像素4B
  Log("FD_FB size=%d",file_table[FD_FB].size);
}
```
之后在device.c中通过fb_write函数来实现显存中图像的绘制。根据显存中像素的排列表，可以将绘制功能分为三种情况：只在一行上绘制，在两行上绘制，绘制三行以上。

然后通过init_device函数将屏幕长宽信息写入dispinfo字符串中

dispinfo_read将字符串dispinfo中offset开始n字节写入buf

```c
//读取dispinfo
void dispinfo_read(void *buf, off_t offset, size_t len) {
  strncpy(buf,dispinfo+offset,len);
}

extern void getScreen(int *width,int *height);
//把buf中len字节写到屏幕上offset处
void fb_write(const void *buf, off_t offset, size_t len) {
  assert(offset%4==0&&len%4==0);//像素以4B为单位
  int index,x1,y1,y2;
  int width=0,height=0;
  getScreen(&width,&height);

  index=offset/4;//像素的索引
  x1=index%width;
  y1=index/width;//行

  index=(offset+len)/4;
  y2=index/width;

  assert(y2>=y1);
  if(y2==y1){//只在一行上绘制
    _draw_rect(buf,x1,y1,len/4,1);//目标，左上角的x，y，长度，行数
    return;
  }
  int tempx=width-x1;
  if(y2-y1==1){//在两行上绘制
    _draw_rect(buf,x1,y1,tempx,1);
    _draw_rect(buf+4*tempx,0,y2,len/4-tempx,1);
    return;
  }
  //三行以上
  _draw_rect(buf,x1,y1,tempx,1);
  int tempy=y2-y1-1;
  _draw_rect(buf+4*tempx,0,y1+1,width,tempy);
  _draw_rect(buf+4*tempx+4*width*tempy,0,y2,len/4-tempx-tempy*width,1);
}

//将屏幕长宽信息写入dispinfo
void init_device() {
  _ioe_init();

  // TODO: print the string to array `dispinfo` with the format
  // described in the Navy-apps convention
  int width=0,height=0;
  getScreen(&width,&height);
  sprintf(dispinfo,"WIDTH:%d\nHEIGHT:%d\n",width,height);
}
```

之后，修改fs.c，设置fb和dispinfo两个特殊文件的读写权限和方法。

```c
extern void dispinfo_read(void *buf, off_t offset, size_t len);
//从fd文件的offset处开始，读最多len个字节到buf中，返回实际字节数
ssize_t fs_read(int fd,void *buf,size_t len){
  assert(fd>=0&&fd<NR_FILES);
  if(fd<3||fd==FD_FB){//不可读取fb
    Log("error:fd<3||fd==FD_DISPINFO");
    return 0;
  }
  int n=fs_filesz(fd)-get_open_offset(fd);//当前文件剩余长度
  if(n>len){
    n=len;//实际读取的长度不能超过n
  }
  if(fd==FD_DISPINFO){
    dispinfo_read(buf,get_open_offset(fd),n);
  }
  else
  //从文件当前的位置读len个字节到buf
    ramdisk_read(buf,disk_offset(fd)+get_open_offset(fd),n);
  //更新偏移量
  set_open_offset(fd,get_open_offset(fd)+n);
  return n;
}

extern void fb_write(const void *buf, off_t offset, size_t len);
//buf写入文件
ssize_t fs_write(int fd,void *buf,size_t len){
  assert(fd>=0&&fd<NR_FILES);
  if(fd<3||fd==FD_DISPINFO){//不可写入dispinfo
    Log("error:fd<3||fd==FD_DISPINFO");
    return 0;
  }
  int n=fs_filesz(fd)-get_open_offset(fd);//当前文件剩余长度
  if(n>len){
    n=len;//实际读取的长度不能超过n
  }
  //对于显存，用fb_write来写
  if(fd==FD_FB){
    fb_write(buf,get_open_offset(fd),n);
  }
  else
    ramdisk_write(buf,disk_offset(fd)+get_open_offset(fd),n);
  //更新偏移量
  set_open_offset(fd,get_open_offset(fd)+n);
  return n;
}
```

加载/bin/bmptest，make run，可以看到ProjectN的LOGO。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\N.png" alt="N" style="zoom: 33%;" />

ProjectN是什么呢，查了一下，对我们已经完成的PA任务们有了一个宏观的认识：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\ProjectN.png" alt="ProjectN" style="zoom:80%;" />

#### 2.把设备输入抽象成文件

现在我们把输入事件也抽象成文件，存在/dev/events中。用户程序可以从中一次读出一个输入事件。

需要实现两种事件：按键事件和时钟事件，优先处理按键事件。

device.c中events_read函数对按键事件和时钟事件分别进行处理，负责把发生的事件输出到buf字符串中，其中t uptime代表系统启动后的时间（ms），kd（按下），ku（弹起）。
```c
unsigned long _uptime();//返回系统启动后经过的毫秒数
extern int _read_key();//获得按键的键盘码，若无按键，则返回_KEY_NONE
//把事件写入buf中，最长len字节，返回实际写入字节数
size_t events_read(void *buf, size_t len) {
  char str[20];
  bool down=false;
  int key=_read_key();
  if(key&0x8000){
    key^=0x8000;//获得按键位置
    down=true;
  }
  if(key!=_KEY_NONE){
    sprintf(str,"%s %s\n",down?"kd":"ku",keyname[key]);//按键事件
  }
  else{
    sprintf(str,"t %d\n",_uptime());//时钟事件
  }
  if(strlen(str)<=len){
    strncpy((char*)buf,str,strlen(str));
    return strlen(str);
  }
  Log("error:strlen(str)>len");
  return 0;
}
```
fs.c中给fs_read加入对事件抽象成的文件的读取方法

注意：/dev/events文件（fd=31）只是不断地提供机会，让我们可以处理输入事件，而并不说明具体是哪些事件。而当我们产生输入事件以后，会将具体的事件抽象成文件（fd=4，即FD_EVENTS），这时候调用events_read函数输出结果。

```c
  //对于事件抽象成的文件
  if(fd==FD_EVENTS){
    return events_read(buf,len);//这里len作为events_read函数中的最大长度上限，所以直接返回即可
  }
```

尝试运行，发现超级慢，后来关上了common.h中DEBUG的宏定义，就很流畅了：

![events](C:\Users\Mika\Desktop\综合课程设计\pa3pic\events.png)

#### 3.运行仙剑奇侠传

<img src="C:\Users\Mika\Desktop\综合课程设计\pa3pic\仙剑.png" alt="仙剑" style="zoom:60%;" />

### 四、必答题

> 文件读写的具体过程 仙剑奇侠传中有以下行为：
>
> 在 navy-apps/apps/pal/src/global/global.c 的 PAL_LoadGame()中通过 fread()读取游戏存档 
>
> 在 navy-apps/apps/pal/src/hal/hal.c 的 redraw()中通过 NDL_DrawRect()更新屏幕
>
> 请结合代码解释仙剑奇侠传,库函数,libos,Nanos-lite,AM,NEMU 是如何相互协助,来分别完成游戏存档的读取和屏幕的更新

global.c

```c
   //
   // Read all data from the file and close.
   //
   fread(&s, sizeof(SAVEDGAME), 1, fp);
   fclose(fp);
```

hal.c

```c
static void redraw() {
  for (int i = 0; i < W; i ++)
    for (int j = 0; j < H; j ++)
      fb[i + j * W] = palette[vmem[i + j * W]];

  NDL_DrawRect(fb, 0, 0, W, H);
  NDL_Render();
}
```

ndl.c：

NDL_DrawRect把所有像素节点写入canvas数组

NDL_Render把canvas写入fb，然后用fflush刷新屏幕，相当于绘制图像

```c
int NDL_DrawRect(uint32_t *pixels, int x, int y, int w, int h) {
  if (has_nwm) {
    for (int i = 0; i < h; i ++) {
      printf("\033[X%d;%d", x, y + i);
      for (int j = 0; j < w; j ++) {
        putchar(';');
        fwrite(&pixels[i * w + j], 1, 4, stdout);
      }
      printf("d\n");
    }
  } else {
    for (int i = 0; i < h; i ++) {
      for (int j = 0; j < w; j ++) {
        canvas[(i + y) * canvas_w + (j + x)] = pixels[i * w + j];
      }
    }
  }
}

int NDL_Render() {
  if (has_nwm) {
    fflush(stdout);
  } else {
    for (int i = 0; i < canvas_h; i ++) {
      fseek(fbdev, ((i + pad_y) * screen_w + pad_x) * sizeof(uint32_t), SEEK_SET);
      fwrite(&canvas[i * canvas_w], sizeof(uint32_t), canvas_w, fbdev);
    }
    fflush(fbdev);
  }
}
```

可以看出，上面的代码都是使用fread，fwrite，fseek，fflush等库函数来完成工作的。

以写文件为例，库函数fwrite调用libc中的write函数，write调用libos中的\_write函数，\_write调用\_syscall\_，\_syscall_再通过内联汇编int 0x80指令进行系统调用。

之后，nemu执行int指令，这样就进入了阶段一中描述的异常处理的过程，根据idt跳转到AM的目标地址。在AM中保存现场，将异常封装成事件，操作系统Nanos-lite使用do_event对事件进行分发，发现时系统调用事件后，使用do_syscall来执行各种系统调用函数，如sys_write。

sys_write中使用fs_write对文件进行写入

```c
//fd是文件描述符，将要把buf中的len字节输出
int sys_write(int fd,void *buf,size_t len){
  if(fd==1||fd==2){//写入stdout或stderr
    char c;
    // Log("qwq");
    for(int i=0;i<len;++i){
      memcpy(&c,buf+i,1);
      _putc(c);
    }
    return len;
  }
  if(fd>=3){
    return fs_write(fd,buf,len);
  }
  // else panic("Unhandled fd=%d in sys_write",fd);
  Log("fd<=0");
  return -1;
}
```

fs_write根据文件描述符的不同，对不同文件采用不同的写方法，比如对于显存，用fb_write来写；对于磁盘上的一般文件，用ramdisk_write来写。但在PA中，它们本质上都被映射到内存中。

```c
//buf写入文件
ssize_t fs_write(int fd,void *buf,size_t len){
  assert(fd>=0&&fd<NR_FILES);
  if(fd<3||fd==FD_DISPINFO){//不可写入dispinfo
    Log("error:fd<3||fd==FD_DISPINFO");
    return 0;
  }
  int n=fs_filesz(fd)-get_open_offset(fd);//当前文件剩余长度
  if(n>len){
    n=len;//实际读取的长度不能超过n
  }
  //对于显存，用fb_write来写
  if(fd==FD_FB){
    fb_write(buf,get_open_offset(fd),n);
  }
  else
    ramdisk_write(buf,disk_offset(fd)+get_open_offset(fd),n);
  //更新偏移量
  set_open_offset(fd,get_open_offset(fd)+n);
  return n;
}
```

至此，PA3第三阶段到此结束。
