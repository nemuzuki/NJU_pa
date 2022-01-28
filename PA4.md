## PA4 - 虚实交错的魔法：分时多任务

### 一、虚拟空间与分页机制

#### 虚拟地址空间

nanos-lite目前只是一个单任务的操作系统，为了同时运行多个程序，需要采用分时技术，不断在进程之间快速切换。而另一个必要条件就是不同的进程要有独立的存储空间。

我们希望loader直接把不同的程序加载到内存的不同位置，但是我们不能保证程序将来运行的时候用到的内存是空闲的。一种解决方法是采用PIC（位置无关代码），在链接的阶段先不确定位置，加载阶段再填写一个全局偏移量表，但目前难以实现。

另一种方法是采用虚拟内存。虚拟内存是在物理内存之上给程序使用的抽象，可以让程序被链接到固定位置（其实是虚拟地址），但实际上会被加载到不同的位置执行。

引入虚拟内存后，eip是虚拟地址，我们需要利用MMU（内存管理单元）进行虚拟地址到物理地址的映射。而操作系统则决定虚拟地址映射到哪个物理地址。

#### 分段机制

把物理内存划分成若干段，不同的程序在不同段上运行。在MMU中实现段基址寄存器，用虚拟地址+偏移量（段基址）得到物理地址。

#### 超越容量的界限——分页机制

虚拟内存的目的其实是扩充内存，程序在一次运行中实际上只用小部分代码，使用分段机制的粒度太大，所以分成更小的片段（页面）组织，这就是分页机制。

分页机制使用页表（Page Table）记录虚拟页到物理页（Page Frame）的映射，加载程序时，操作系统就给程序分配物理页（不需要连续），每个程序都有自己的页表。程序运行时，操作系统把页表放入MMU，拿到一个虚拟地址，就可以让MMU通过页表进行映射。

i386是x86架构首次使用分页机制的处理器，页面大小为4KB，采用二级页表。第一级页表也叫**页目录**（Page Directory），每个页表项长度是4B，每个页表4KB，有1024个页表项。i386使用CR3寄存器来存放页目录的基地址。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa4pic\1.png" alt="1" style="zoom:80%;" />

> i386 不是一个 32 位的处理器吗,为什么表项中的基地址信息只有 20 位,而不是 32 位? 
>
> 手册上提到表项(包括 CR3)中的基地址都是物理地址,物理地址是必须的吗?能否使用虚拟地址? 
>
> 为什么不采用一级页表?或者说采用一级页表会有什么缺点?

页表项的基址拼上虚拟地址的低12位页内偏移得到物理地址

不能，如果用虚拟地址，那还是要通过页目录才能找到物理地址，可是我们现在要找的就是页目录的位置

一张一级页表只能映射到1024*4KB=4MB的物理空间，太小了。要想映射整个虚拟空间，需要一张庞大的页表。



页表项的标志位

present位：表示映射的物理页是否有效，无效时有两种可能：物理页被换回磁盘；该虚拟地址还没有映射到物理页

R/W位：是否可写

U/S位：访问物理页的权限，ring 3 or ring 0



分页机制可以使用超过物理地址上限的虚拟地址，只要保证这个虚拟地址映射到的物理地址不越界即可

#### 加入PTE

AM中，PTE模块负责存储保护，打开宏定义HAS_PTE后，即可使用MM（存储管理器）模块，负责分页相关的存储管理。

#### 准备内核页表

添加CR3和CR0寄存器及其相应的操作指令

<img src="C:\Users\Mika\Desktop\综合课程设计\pa4pic\first run.png" alt="first run" style="zoom:80%;" />

发现缺少的是cr3的mov指令

![101713](C:\Users\Mika\Desktop\综合课程设计\pa4pic\101713.png)

##### CR寄存器

CR寄存器全称是Control Registers（控制寄存器），共有0到4四个，用于控制和确定处理器的操作模式以及当前执行任务的特性。

![controlregs](C:\Users\Mika\Desktop\综合课程设计\pa4pic\controlregs.png)

CR0寄存器负责开启分页机制，当CR0的PG位（最高位）为1时，开启分页机制，从此PA3中所有对地址的访问方法(vaddr_read, vaddr_write)就不再是访问物理地址了，而是虚拟地址，需要经过分页地址转换。

CR3是页目录基址寄存器，里面存的是一级页表的基址，由于页表大小均为4K，存在4K为单位的边界上，所以该地址低12位总为0。`mov %eax, %cr3`指令也就是将一级页表基址从cr3寄存器中读取到通用寄存器中。

##### 实现cr寄存器mov指令

首先在reg.h中添加CR3和CR0寄存器
```c
  uint32_t CR0;
  uint32_t CR3;
  
} CPU_state;
```
在monitor.c的restart中初始化cpu.CR0=0x60000011;

在rtl.h中定义cr寄存器的读写rtl指令rtl_load_cr和rtl_store_cr
```c
static inline void rtl_load_cr(rtlreg_t *dest, int r){
  switch(r){
    case 0:*dest=cpu.CR0;return;
    case 3:*dest=cpu.CR3;return;
    default:assert(0);
  }
  return;
}
static inline void rtl_store_cr(int r,const rtlreg_t *src){
  switch(r){
    case 0:cpu.CR0=*src;return;
    case 3:cpu.CR3=*src;return;
    default:assert(0);
  }
  return;
}
```

接着定义读写cr寄存器的译码函数和执行函数。

```c
decode.c:
make_DHelper(mov_load_cr){
  //将两个操作数读入id_dest和id_src
  decode_op_rm(eip,id_dest,false,id_src,false);
  rtl_load_cr(&id_src->val,id_src->reg);//reg为0或3，把相应寄存器内容读到src
}

make_DHelper(mov_store_cr){
  decode_op_rm(eip,id_src,true,id_dest,false);
}

data-mov.c:
make_EHelper(mov_store_cr){
  rtl_store_cr(id_dest->reg,&id_src->val);//把数据写入cr寄存器
  print_asm_template2(mov);
}
```

为了验证cr寄存器的功能，在info r的命令里面加入对CR0和CR3的展示，make run运行仙剑后si 2000，然后查看寄存器的值，可以看到CR0和CR3值的变化：

![crvalues](C:\Users\Mika\Desktop\综合课程设计\pa4pic\crvalues.png)

开始CR0=0x60000011，最高位为0（0x6=0b0110），现在CR0最高位为变为1（0xe=0b1110），说明开启了分页机制；CR3也从一开始的0变为了页目录基址，而且末12位全为0，说明是正确的4K边界地址。

##### 根据虚拟地址访存

现在我们要实现的是已知虚拟地址，访问物理页的过程。

首先需要引入头文件mmu.h，里面定义了CR0和CR3的真正结构。

然后添加一些解析虚拟地址的宏定义，例如PTE_ADDR是获得某个地址的高20位，CR3高20位是页目录基址，页目录项里存的高20位是页表基址

memory.c：

```c
#include "memory/mmu.h"
//获取高20位，是xx的基址
#define PTE_ADDR(pte)   ((uint32_t)(pte) & ~0xfff)
//从虚拟地址得到10bit页目录的index/10bit页表index/12bit页内偏移
#define PDX(va)     (((uint32_t)(va) >> 22) & 0x3ff)
#define PTX(va)     (((uint32_t)(va) >> 12) & 0x3ff)
#define OFF(va)     ((uint32_t)(va) & 0xfff)
```

之后就是最重要的将虚拟地址按照分页机制解析成物理地址的方法了，在page_translate函数中实现。

- cr3的高20位是页目录表基址，拼上虚拟地址的高10位得到页目录项
- 页目录项的高20位是页表基址，拼上虚拟地址的中间10位得到页表项
- 将页表项物理页基址与虚拟地址末12位页内偏移拼起来得到物理地址

```c
//根据虚拟地址addr解析出物理地址
paddr_t page_translate(vaddr_t addr, bool iswrite){
  CR0 cr0=(CR0)cpu.CR0;//mmu.h中定义了CR0的结构
  if(cr0.paging&&cr0.protect_enable){//如果是分页机制，保护模式
    CR3 cr3=(CR3)cpu.CR3;
    PDE *pgdirs=(PDE*)PTE_ADDR(cr3.val);//cr3的高20位是页目录表基址
    PDE pde=(PDE)paddr_read((uint32_t)(pgdirs+PDX(addr)),4);//在内存中的页目录找到正确的页目录项

    PTE *ptab=(PTE*)PTE_ADDR(pde.val);//页目录项的高20位是页表基址
    PTE pte=(PTE)paddr_read((uint32_t)(ptab+PTX(addr)),4);//页表项

    pde.accessed=1;
    pte.accessed=1;
    if(iswrite){
      pte.dirty=1;
    }

    paddr_t paddr=PTE_ADDR(pte.val)|OFF(addr);//将物理页基址与页内偏移拼起来得到物理地址
    return paddr;
  }
  return addr;
}
```

有了映射方法，那么对于虚拟内存的读写就应运而生了，先用page_translate转换，再用paddr_xxx即可读写。

注意跨两个虚拟页的data的读取，需要先得到两个页的字节数，然后分别去访存，最后把两页的数据拼接起来即可。

```c
//根据虚拟地址读取len个字节的内存，返回数据
uint32_t vaddr_read(vaddr_t addr, int len) {
  if(PTE_ADDR(addr)!=PTE_ADDR(addr+len-1)){//要读取内容的首开头和结尾对应的页目录基址不同，即要读取的内容跨了两个页
    int len1=0x1000-OFF(addr);//第一页要读的字节数
    int len2=len-len1;
    paddr_t paddr1=page_translate(addr,true);
    paddr_t paddr2=page_translate(addr+len1,true);
    
    uint32_t low=paddr_read(paddr1,len1);
    uint32_t high=paddr_read(paddr2,len2);

    return high<<(8*len1)|low;//返回拼接后的数据
  }
  else{
    paddr_t paddr=page_translate(addr,false);
    return paddr_read(paddr,len);
  }
}

//将len字节的data写到虚拟地址addr处
void vaddr_write(vaddr_t addr, int len, uint32_t data) {
    if(PTE_ADDR(addr)!=PTE_ADDR(addr+len-1)){//内容跨了两个页
      int len1=0x1000-OFF(addr);//第一页要读的字节数
      int len2=len-len1;
      paddr_t paddr1=page_translate(addr,false);
      paddr_t paddr2=page_translate(addr+len1,false);
      //将要写的数据拆分成两部分
      uint32_t low=data & (~0u >> ((4 - len1) << 3));
      uint32_t high=data>>((4-len2)*8);

      paddr_write(paddr1, len1, low);
      paddr_write(paddr2, len2, high);
      return;
    }
    else{
      paddr_t paddr=page_translate(addr,true);
      paddr_write(paddr, len, data);
    }
}
```

之后即可成功运行仙剑。

注意：本节中，AM的init_mm调用_pte_init()函数填写的是内核页表，所以程序只能运行在内核虚拟空间上

#### 让用户程序运行在分页机制上

<font color=#ff0000>之前仙剑运行在内核的虚拟空间上，而不是用户空间上</font>，因为所有进程都能共享内核空间，这样就有权限问题和进程覆盖问题。为了让用户程序运行在操作系统为其分配的虚拟地址空间之上，需要将链接地址从0x4000000改为0x8048000，这个地址实际上超过了物理地址最大值，只有这样才能保证操作系统不把这块内存分配给其他进程。这样操作系统再通过MM将这个虚拟地址映射为物理地址即可，通过页表项里面的标志位，可以知道该物理页被占用了，不能被其他进程覆盖。

本节实现从磁盘加载程序到物理页，并在页表项中填写虚拟页->物理页映射的过程。

**注意这一节和上一节的区别，这一节是在用户进程的页表中添加映射，而上一节_pte_init函数实现的是内核页表的填写。**前面也能运行仙剑，但是在内核空间中物理地址是固定的，而且操作系统没有对空闲的物理内存进行管理；而这一节中，我们的操作系统就可以自由申请物理页，再使用虚拟地址去进行映射。

pte.c

在页表项中添加虚拟地址到物理地址的映射。注意如果页目录项有效位为0，即没有对应的页表，首先需要申请一个页作为页表，然后添加页目录项到页表的映射。p是虚拟地址空间

```c
//添加va->pa的映射
void _map(_Protect *p, void *va, void *pa) {
  PDE *pgdir=(PDE*)p->ptr;//页目录表基址
  PTE *pgtab=NULL;//页表基址

  PDE *pde=pgdir+PDX(va);//页目录项
  if((*pde&PTE_P)==0){//页目录项有效位为0，即没有对应的页表
    pgtab=(PTE*)palloc_f();//申请一个页
    *pde=(uintptr_t)pgtab|PTE_P;//填写页目录项，添加映射
  }

  pgtab=(PTE*)PTE_ADDR(*pde);
  PTE *pte=pgtab+PTX(va);//页表项
  *pte=(uintptr_t)pa|PTE_P;//填写页表项，添加映射
}
```
修改main.c，使用load_prog函数来加载程序。load_prog先创建一个用户进程的虚拟地址空间，然后再调用loader

loader.c

在加载磁盘上的文件后，先确定大小，从而确定需要的物理页数量（注意向上取整）。之后从0x8048000开始不断将虚拟地址与申请的物理页建立映射关系，这样就完成了用户程序加载到用户虚拟空间上。

```c
uintptr_t loader(_Protect *as, const char *filename) {
  //TODO();
  // ramdisk_read(DEFAULT_ENTRY,0,RAMDISK_SIZE);//PA3.1

  int fd=fs_open(filename,0,0);
  Log("filename=%s,fd=%d",filename,fd);
  //fs_read(fd,DEFAULT_ENTRY,fs_filesz(fd));
  int size=fs_filesz(fd);
  int page_num=(size+PGSIZE-1)/PGSIZE;//页面数量

  void *pa=NULL;
  void *va=DEFAULT_ENTRY;//虚拟空间
  for(int i=0;i<page_num;++i){//不断根据虚拟地址读取物理页
    pa=new_page();//申请物理页
    _map(as,va,pa);//建立映射
    fs_read(fd,pa,PGSIZE);//读物理页
    va+=PGSIZE;
  }
  fs_close(fd);

  return (uintptr_t)DEFAULT_ENTRY;
}
```

之后运行dummy，即可成功。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa4pic\dummy.png" alt="dummy" style="zoom:80%;" />

##### 内核映射的作用

_protect函数中的循环用于拷贝内核映射，即将内核页表的va->pa映射拷贝给用户进程的页表。因为所有用户进程都共享内核空间，所以内核态页表的内容也需要共享，缺少的话会发生缺页。

```c
void _protect(_Protect *p) {
  PDE *updir = (PDE*)(palloc_f());
  p->ptr = updir;
  // map kernel space
  for (int i = 0; i < NR_PDE; i ++) {
    updir[i] = kpdirs[i];
  }
```

##### 堆区管理结合虚拟内存

回顾PA3，当用户程序申请内存时，系统调用sys_brk总是返回0，表示堆区大小的调整总是成功。而现在用户程序运行在虚拟空间上，申请了内存以后还需视情况把这部分内存再与虚拟空间映射。

设当前堆指针所在位置是max_brk，需要申请的堆区一直到new_brk处。设first为需要新增映射的第一个页面的虚拟首地址，end为需要新增映射的最后一个页面的虚拟首地址。PGROUNDUP将虚拟地址向上4K对齐，PGROUNDDOWN将虚拟地址向下4K对齐。这时要考虑多种情况：

（一）max_brk和new_brk就在一页中：无需增加映射

（二）max_brk和new_brk不在一页中：

(1)如果max_brk页对齐，那么first就是max_brk，否则first是PGROUNDUP(max_brk)

(2)如果new_brk页对齐，那么end就是PGROUNDDOWN(new_brk)的上一个页，否则first是PGROUNDDOWN(new_brk)。

mm.c
```c
/* The brk() system call handler. */
//堆区申请，并建立虚拟空间映射。new_brk是需要申请堆区的结束位置
int mm_brk(uint32_t new_brk) {
  if(current->cur_brk==0){//初始化当前指针
    current->cur_brk=current->max_brk=new_brk;
  }
  else{
    if(new_brk > current->max_brk){
      uint32_t first=PGROUNDUP(current->max_brk);
      uint32_t end=PGROUNDDOWN(new_brk);
      if((new_brk&0xfff)==0){//结尾4K对齐，少申请一页
        end-=PGSIZE;
      }
      for(uint32_t va=first;va<=end;va+=PGSIZE){
        void *pa=new_page();//申请物理页
        _map(&(current->as),(void*)va,pa);//建立映射
      }
      current->max_brk=new_brk;
    }
    current->cur_brk=new_brk;//更新当前指针
  }
  return 0;
}
```
syscall.c
```c
int sys_brk(int addr){
  //return 0;
  extern int mm_brk(uint32_t new_brk);
  return mm_brk(addr);
}
```

make update后，即可运行仙剑，第一阶段到此结束。

### 二、进程间切换

#### 上下文切换

现在用户程序已经能够运行在相互独立的虚拟地址空间上了，但是CPU为了分时处理它们，还需要实现上下文切换，来不断处理新的进程。与中断处理一样，需要依靠trapframe来保存上下文。

从进程A切换到进程B时，先触发一个中断，把A的tf保存到A的堆栈上，然后将栈顶指针指向B的堆栈，恢复现场时就会将B的通用寄存器的值赋予CPU，这样就完成了进程切换。

首先我们要定义内核自陷中断。内核自陷中断通过int $0x81指令触发，需要和PA3一样完成该中断的相关处理信息的填写。

nexus-am/am/arch/x86-nemu/src/asye.c

```c
void _trap() {
  asm volatile("int $0x81");
}

  case 0x81: ev.event = _EVENT_TRAP;break;

  idt[0x81] = GATE(STS_TG32, KSEL(SEG_KCODE), vecself, DPL_USER);
```

由于还没有实现进程调度，所以运行会遇到panic

<img src="C:\Users\Mika\Desktop\综合课程设计\pa4pic\内核自陷.png" alt="内核自陷" style="zoom:80%;" />

每个进程有一个进程控制块PCB，包含：陷阱帧位置tf，虚拟空间as，记录用户堆区位置的cur_brk和max_brk，32KB的堆栈stack（注意前面四个信息包含在stack中）

proc.h


```c
typedef union {
  uint8_t stack[STACK_SIZE] PG_ALIGN;
  struct {
    _RegSet *tf;
    _Protect as;
    uintptr_t cur_brk;
    // we do not free memory, so use `max_brk' to determine when to call _map()
    uintptr_t max_brk;
  };
} PCB;
```


pte.c

\_umake函数负责创建用户进程的现场，它在ustack底部初始化一个tf，以entry为返回地址。为了让程序能通过\_start入口函数运行，还需要设置\_start的栈帧（三个参数分别是int,char*,char*类型，倒序压栈），然后压栈_start的返回地址（0）。总的压栈过程是：\_start的栈帧，tf，tf的基地址。
```c
//创建用户进程的现场
_RegSet *_umake(_Protect *p, _Area ustack, _Area kstack, void *entry, char *const argv[], char *const envp[]) {
  extern void *memcpy(void *,const void*,int);
  //设置_start()的栈帧
  int arg1=0;
  char *arg2=NULL;
  memcpy((void*)ustack.end-4,(void*)arg2,4);
  memcpy((void*)ustack.end-8,(void*)arg2,4);
  memcpy((void*)ustack.end-12,(void*)arg1,4);
  memcpy((void*)ustack.end-16,(void*)arg1,4);
  //trapframe
  _RegSet tf;
  tf.eflags=0x02;
  tf.cs=8;
  tf.eip=(uintptr_t)entry;//返回地址为entry
  void *ptf=(void*)(ustack.end-16-sizeof(_RegSet));//tf的基址
  memcpy(ptf,(void*)&tf,sizeof(_RegSet));//把tf压栈

  return (_RegSet*)ptf;
}
```
之后就是使用schedule进行进程调度了，本质上就是返回新的进程的tf，默认切换到第一个用户进程（其实就是仙剑）。同时修改事件分发函数。
```c
//进程调度
_RegSet* schedule(_RegSet *prev) {
  // return NULL;
  if(current!=NULL){//current:当前进程的PCB指针
    current->tf=prev;//保存tf
  }
  current=&pcb[0];//切换到第一个用户进程
  _switch(&current->as);//切换虚拟地址空间
  return current->tf;
}

static _RegSet* do_event(_Event e, _RegSet* r) {
  switch (e.event) {
    case(_EVENT_SYSCALL):
      return do_syscall(r);
    case(_EVENT_TRAP):
      printf("self-trapped event!\n");
      return schedule(r);//返回新的进程的tf
    default: panic("Unhandled event ID = %d", e.event);
  }

  return NULL;
}
```
trap.S

asm_trap中，中断处理函数irq_handle将tf的位置作为返回值存放在eax中，我们现在将它赋给esp，这样就将栈顶切换到新进程的tf了。
```asm
#----|-------entry-------|-errorcode-|---irq id---|---handler---|
.globl vecsys;    vecsys:  pushl $0;  pushl $0x80; jmp asm_trap
.globl vecnull;  vecnull:  pushl $0;  pushl   $-1; jmp asm_trap
.globl vecself;  vecself:  pushl $0;  pushl $0x81; jmp asm_trap

asm_trap:
  pushal

  pushl %esp
  call irq_handle

  #addl $4, %esp
  movl %eax,%esp

  popal
  addl $8, %esp

  iret
```
#### :star:进程切换总结

总结一下，main.c中我们用load_prog加载程序，后者调用umake创建当前用户进程的现场，主要是设置trapframe。当需要进程切换时，首先通过\_trap函数使用int $0x81指令产生内核自陷中断，查看反汇编代码可以看到调用了vecself，它会跳转到asm_trap，将当前进程的现场tf压栈后，就调用irq_handle来进行事件分发，从而do_event函数发现是内核自陷中断后调用schedule来进行进程调度，其实就是返回新进程的PCB中的tf指针。这个返回值保存在eax中，把它赋给esp，就完成了栈顶切换到新进程的tf。

现在我们就可以通过内核自陷触发上下文切换的方式运行仙剑了。

#### 分时多任务

现在我们可以通过修改调度函数schedule来实现分时多任务了，也就是给不同的进程分配不同长度的时间片，使它们并发执行。具体方法是当仙剑（进程1）被调度1000次后，切换成hello（进程2）执行一次，通过一个静态的计数器num来记录次数。

```c
//进程调度
_RegSet* schedule(_RegSet *prev) {
  // return NULL;
  if(current!=NULL){//current:当前进程的PCB指针
    current->tf=prev;//保存tf
  }
  // current=(current==&pcb[0]?&pcb[1]:&pcb[0]);
  // Log("ptr=0x%x\n",(uintptr_t)current->as.ptr);
  else{
    current=&pcb[0];//初始进程为0号进程
  }
  static int num=0;
  static const int freq=1000;
  if(current==&pcb[0]){
    num++;
  }
  else{
    current=&pcb[0];
  }
  if(num==freq){//如果到达1000次，则切换成进程1
    current=&pcb[1];
    num=0;
  }
  _switch(&current->as);//切换虚拟地址空间
  return current->tf;
}
```

最后，**我们还需要选择一个时机来触发进程调度，比较合适的时机就是处理系统调用之后**，对于仙剑系统调用就是显示屏幕，对于hello系统调用就是将字符串输出到串口。对于事件分发函数中_EVENT_SYSCALL的情况需要修改，在处理完系统调用do_syscall之后进行调度。

```c
static _RegSet* do_event(_Event e, _RegSet* r) {
  switch (e.event) {
    case(_EVENT_SYSCALL):
      //return do_syscall(r);
      do_syscall(r);
      return schedule(r);//返回新的进程的tf
    case(_EVENT_TRAP):
      printf("self-trapped event!\n");
      return schedule(r);//返回新的进程的tf
    default: panic("Unhandled event ID = %d", e.event);
  }

  return NULL;
}
```

在main.c中，加载仙剑和hello两个程序，注意这并不代表它们就按这个顺序执行，只是加载到了内存，还需要trap来辅助进行进程间的调度和切换。

```c
  load_prog("/bin/pal");
  load_prog("/bin/hello");
  _trap();
```

最终可以看到，两个程序并发执行：

![分时](C:\Users\Mika\Desktop\综合课程设计\pa4pic\分时.png)

第二阶段到此结束。

### 三、外部中断

#### 来自外部的声音

阶段二完成的分时多任务是依赖系统调用进行进程调度的，但是并不是所有进程都会系统调用，所以需要其他机制。硬件中断机制就可以实现这个功能，让时钟主动通知CPU，而不是被动地等着CPU来访问。

CPU需要增加一个INTR引脚，一旦外部设备发出中断请求，就让INTR电平为高。CPU每执行完一条指令，就检查INTR引脚，看是否为高电平。

```c
  bool INTR;//INTR引脚
} CPU_state;

void dev_raise_intr() {
  cpu.INTR=true;
}

exec_wrapper:
  if(cpu.eflags.IF & cpu.INTR){//开启中断，并且收到中断信号
    cpu.INTR=false;
    raise_intr(TIME_IRQ,cpu.eip);
    update_eip();
  }
```

时钟中断的中断号是32。此外，还需要_umake中设置开中断，在raise_intr中保存eflags之后关闭中断，保证处理中断的时候不被中断打断。

```c
idt[32] = GATE(STS_TG32, KSEL(SEG_KCODE), vectime, DPL_USER);

case 32: ev.event = _EVENT_IRQ_TIME;break;

trap.S:
  .globl vectime;  vectime:  pushl $0;  pushl $32; jmp asm_trap
  
_umake:
  tf.eflags=0x02|FL_IF;//设置开中断

raise_intr:
  //TODO();
  memcpy(&t1,&cpu.eflags,sizeof(cpu.eflags));
  rtl_li(&t0,t1);
  rtl_push(&t0);//eflags
  cpu.eflags.IF=0;//处理中断的时候需要关闭中断
  rtl_push(&cpu.cs);//cs
  rtl_li(&t0,ret_addr);
  rtl_push(&t0);//eip
```

然后把进程调度的条件改成时钟中断_EVENT_IRQ_TIME：

```c
static _RegSet* do_event(_Event e, _RegSet* r) {
  switch (e.event) {
    case(_EVENT_SYSCALL):
      return do_syscall(r);
    case(_EVENT_TRAP):
      printf("self-trapped event!\n");
      return schedule(r);//返回新的进程的tf
    case(_EVENT_):
      return schedule(r);//通过时钟中断进行进程调度
    default: panic("Unhandled event ID = %d", e.event);
  }
  return NULL;
}
```

在schedule里面hello的情况加上Log输出，运行，即可看到进程调度依赖于时钟中断：

![时钟中断](C:\Users\Mika\Desktop\综合课程设计\pa4pic\时钟中断.png)

### 四、必答题

> 请结合代码,解释分页机制和硬件中断是如何支撑仙剑奇侠传和 hello 程序在我们的计算机系统 (Nanos-lite, AM, NEMU)中分时运行的.

1.分页机制

首先，nemu这一平台提供了CR0和CR3寄存器，CR0寄存器负责开启分页机制，CR3寄存器存储页目录基址。MMU进行虚拟地址到物理地址的转换，通过vaddr_read, vaddr_write进行对虚拟地址的访问。

我们准备了内核页表用于访问内核虚拟空间。AM的init_mm调用_pte_init函数填写了内核页表。

为了在用户空间上加载用户程序，nanos-lite使用load_prog函数来加载程序，调用_protect函数将内核页表的内容拷贝到用户进程的页表，然后loader加载程序。当不断分配从0x8048000开始的虚拟地址后，用new_page申请物理页，然后用将va->pa的映射加入页表。

2.硬件中断与进程调度

为了实现进程调度，需要用umake来创建进程的上下文，保存在trap frame中。当需要进程切换时，就通过硬件产生一个外部中断（这里是时钟中断IRQ_TIME），封装成事件并进行分发。中断处理时，将旧进程的tf压栈，使用schedule函数得到新进程的tf地址，asm_trap让栈顶指针指向它，中断返回时就完成了进程切换。

### 五、编写不朽的传奇

最后我们需要实现按下键盘上的F12，使得仙剑和videotest能够不断切换，同时并发运行hello。

首先定义switch_current_game实现游戏切换，schedule中定义每个游戏时间片为1000，最后_read_key设置当按下F12后进行游戏切换（我的笔记本还得同时按Fn）。


```c
main.c:
load_prog("/bin/pal");
load_prog("/bin/hello");
load_prog("/bin/videotest");

proc.c:
int current_game=0;
void switch_current_game(){
  current_game=(current_game==0?2:0);
  Log("current_game=%d\n",current_game);
}

schedule:
  if(current==&pcb[current_game]){
    num++;
  }
  else{
    current=&pcb[current_game];
  }

_read_key:
  if(key==_KEY_F12 && down){//按下F12，切换游戏
    extern void switch_current_game();
    switch_current_game();
  }
```
运行发现ndl.c中屏幕的参数有错误，这实际上是因为每次切换回来文件，读写指针没有回到文件开头导致的，所以需要在fs_open中加入set_open_offset(i,0);

![bad_ptr](C:\Users\Mika\Desktop\综合课程设计\pa4pic\bad_ptr.png)

```c
//打开文件，返回文件标识符
int fs_open(const char *filename,int flags,int mode){
  for(int i=0;i<NR_FILES;++i){
    if(strcmp(filename,file_table[i].name)==0){
      set_open_offset(i,0);//设置读写指针到文件开头
      return i;
    }
  }
  panic("file not exist in file_table!");
  return -1;
}
```

这样一来，就成功实现了按下F12使得仙剑和videotest来回切换。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa4pic\switch_game.png" alt="switch_game"  />

PA4就到此结束啦！
