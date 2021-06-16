## PA2-简单复杂的机器：冯诺依曼计算机系统 实验报告

学号：1813055

姓名：赵书楠

PA2主要分为两大部分，第一部分是实现大量指令的译码函数和执行函数，通过c程序测试；第二部分是完成CPU与I/O设备交互的工作。

### 一、实现新指令

#### 0.两个重要的数据结构

（1）opcode_table（译码查找表，位于cpu/exec/exec.c）：

里面的每一个元素opcode_entry都是一个结构体，存储了相应指令的译码函数（将操作数译码的方法）、执行函数、操作数宽度

```c
 /* 0x88 */	IDEXW(mov_G2E, mov, 1), IDEX(mov_G2E, mov), IDEXW(mov_E2G, mov, 1), IDEX(mov_E2G, mov),

typedef struct {
  DHelper decode;
  EHelper execute;
  int width;
} opcode_entry;
```

（2）decoding（全局译码信息，位于nemu/src/cpu/decode/decode.c）：

```c
typedef struct {
  uint32_t opcode;
  vaddr_t seq_eip;  // sequential eip
  bool is_operand_size_16;
  uint8_t ext_opcode;
  bool is_jmp;
  vaddr_t jmp_eip;
  Operand src, dest, src2;
#ifdef DEBUG
  char assembly[80];
  char asm_buf[128];
  char *p;
#endif
} DecodeInfo;
```

根据decoding的src, dest, src2三个成员，在include/cpu/decode.h中定义了三个宏 id_src,id_src2 和 id_dest，分别代表两个源操作数和一个目的操作数的Operand结构，该结构体包含了操作数相关信息。

```c
#define id_src (&decoding.src)
#define id_src2 (&decoding.src2)
#define id_dest (&decoding.dest)

typedef struct {
  uint32_t type;
  int width;
  union {
    uint32_t reg;
    rtlreg_t addr;
    uint32_t imm;
    int32_t simm;
  };
  rtlreg_t val;
  char str[OP_STR_SIZE];
} Operand;
```



#### 1.指令的执行过程

记得我们在cpu_exec函数里，每执行一条指令，就会调用一次exec_wrapper函数，其中包括取指、指令译码、指令执行三个步骤。exec_wrapper函数将当前eip中的指令地址保存到decoding.seq_eip中，然后送入exec_real函数去执行。最后通过update_eip对eip进行更新，如果当前需要跳转，那么更新为跳转地址decoding.jmp_eip；否则就是decoding.seq_eip。这样就完成了一条指令的执行。

```c
exec.c:
void exec_wrapper(bool print_flag) {
    ...
    decoding.seq_eip = cpu.eip;//把eip保存至全局译码信息
    exec_real(&decoding.seq_eip);//指令开始执行的入口，在这里seq_eip被更新
    update_eip();
    ...
}

static inline void update_eip(void) {
  cpu.eip = (decoding.is_jmp ? (decoding.is_jmp = 0, decoding.jmp_eip) : decoding.seq_eip);
}
```

exec_real是指令开始执行的入口。它的定义方法非常有趣。在exec.h中有一个名为make_EHelper的宏定义，它的作用是定义一个void类型的函数，而函数名则是"exec_"与make_EHelper的参数name用concat拼接而成。在exec.c中，可以看到使用make_EHelper定义了一个函数（这就是执行函数），这个函数的参数"real"正好与宏定义中的"exec\_"拼接成exec_real，这样就完成了exec_real函数的定义。

```c
exec.h中：
#define make_EHelper(name) void concat(exec_, name) (vaddr_t *eip)
//void exec_real(vaddr_t *eip)

exec.c中：
make_EHelper(real) {
  uint32_t opcode = instr_fetch(eip, 1);//在这里eip会+1
  decoding.opcode = opcode;
  set_width(opcode_table[opcode].width);
  idex(eip, &opcode_table[opcode]);
}
```

在exec_real中可以看到：

- 先用instr_fetch函数取指，即先从eip里读出指令的地址，再更新eip，最后返回指令的第一个字节，这就是指令的操作码opcode。
- 之后将opcode存在全局译码信息decoding中，根据操作码查opcode_table获得操作数的宽度信息，通过set_width函数也存储在decoding中。
- 最后调用idex函数，将操作数用opcode特定的译码函数进行译码。译码函数和exec_real的定义方法完全类似，通过make_DHelper（译码函数）进行定义：

```c
decode.h中：
//专门用来处理op结构体信息
#define make_DopHelper(name) void concat(decode_op_, name) (vaddr_t *eip, Operand *op, bool load_val)
    
#define make_DHelper(name) void concat(decode_, name) (vaddr_t *eip)
```

比如，定义了一个函数make_DHelper(I2r)（即decode_I2r），它的作用是将立即数移入寄存器（I to r）。

```c
static inline make_DopHelper(r) {
  op->type = OP_TYPE_REG;
  op->reg = decoding.opcode & 0x7;
  if (load_val) {
    rtl_lr(&op->val, op->reg, op->width);//将op->reg寄存器中的值存入op->val
  }
}

//立即数译码 
static inline make_DopHelper(I) {
  /* eip here is pointing to the immediate */
  //eip现在指向立即数
  op->type = OP_TYPE_IMM;
  op->imm = instr_fetch(eip, op->width);
  rtl_li(&op->val, op->imm);//将立即数的值写入op->val
}


/* XX <- Ib
 * eXX <- Iv
 */
make_DHelper(I2r) {
  decode_op_r(eip, id_dest, true);//读取id_dest寄存器的值
  decode_op_I(eip, id_src, true);//读取立即数，存入id_src
}
```

对于译码函数的符号，需要如下解释：

| 类型 | 含义                                        |
| ---- | ------------------------------------------- |
| E    | r/m8（8位通用寄存器或者内存）, r/m16, r/m32 |
| G    | r8（8位通用寄存器）, r16, r32（多操作数）   |
| I    | 立即数                                      |
| SI   | 有符号立即数                                |
| a    | al,ax,eax                                   |
| r    | r8, r16, r32（单操作数）                    |



#### 2.RTL：寄存器传输语言

RTL指令使用rtl寄存器来描述指令的行为，rtl寄存器使用一个uint32_t类型的rtlreg_t来定义。分为RTL基本指令和RTL伪指令。

RTL基本指令：最基本的操作

- rtl_li：立即数读取
- rtl_addi, rtl_subi：基本运算
- rtl_lm：从内存读数据，rtl_sm：向内存写数据
- rtl_lr_l, rtl_sr_l：通用寄存器读取

RTL伪指令：利用已实现的rtl指令来实现，如rtl_push

RTL基本指令和RTL伪指令都在include/cpu/rtl.h中实现。例如RTL基本指令rtl_lr_l，它的功能是将编号为r的寄存器的内容赋予dest寄存器；RTL伪指令rtl_lr在此基础上封装，对于不同宽度的寄存器，使用不同的基本指令。

```c
/* RTL basic instructions */
//下面是RTL基本指令
static inline void rtl_lr_l(rtlreg_t* dest, int r) {
  *dest = reg_l(r);
}

/* RTL psuedo instructions */
//下面是RTL伪指令
static inline void rtl_lr(rtlreg_t* dest, int r, int width) {
  switch (width) {
    case 4: rtl_lr_l(dest, r); return;//4字节
    case 1: rtl_lr_b(dest, r); return;//1字节
    case 2: rtl_lr_w(dest, r); return;//2字节
    default: assert(0);
  }
}
```



#### 3.准备工作

首先，修改环境变量三连：

```
export NEMU_HOME=/mnt/hgfs/VMware_shared_folder/ics2018/nemu
export AM_HOME=/mnt/hgfs/VMware_shared_folder/ics2018/nexus-am
export NAVY_HOME=/mnt/hgfs/VMware_shared_folder/ics2018/navy-apps
```

然后，make ARCH=x86-nemu ALL=dummy run，通过nemu对dummy程序进行调试

![1](C:\Users\Mika\Desktop\综合课程设计\pa2pic\1.png)

我们可以通过si单步执行，看从哪行开始无法执行，与反汇编结果nexus-am/tests/cputest/build/dummy-x86-nemu.txt比较。发现需要实现call,push,sub,xor,pop,ret指令。

```asm
/mnt/hgfs/VMware_shared_folder/ics2018/nexus-am/tests/cputest/build/dummy-x86-nemu：     文件格式 elf32-i386


Disassembly of section .text:

00100000 <_start>:
  100000:	bd 00 00 00 00       	mov    $0x0,%ebp
  100005:	bc 00 7c 00 00       	mov    $0x7c00,%esp
  10000a:	e8 01 00 00 00       	call   100010 <_trm_init>
  10000f:	90                   	nop

00100010 <_trm_init>:
  100010:	55                   	push   %ebp
  100011:	89 e5                	mov    %esp,%ebp
  100013:	83 ec 08             	sub    $0x8,%esp
  100016:	e8 05 00 00 00       	call   100020 <main>
  10001b:	d6                   	(bad)  
  10001c:	eb fe                	jmp    10001c <_trm_init+0xc>
  10001e:	66 90                	xchg   %ax,%ax

00100020 <main>:
  100020:	55                   	push   %ebp
  100021:	89 e5                	mov    %esp,%ebp
  100023:	31 c0                	xor    %eax,%eax
  100025:	5d                   	pop    %ebp
  100026:	c3                   	ret    
```



#### 4.实现新指令

对于每条新指令的实现，都要完成以下步骤：

- 实现译码函数make_DHelper
- 实现rtl指令
- 用rtl指令组成正确的执行函数make_EHelper
- 在opcode_table中填写正确的译码函数、执行函数以及操作数宽度

```c
#define IDEXW(id, ex, w)   {concat(decode_, id), concat(exec_, ex), w}//译码函数，执行函数，操作数宽度都有
#define IDEX(id, ex)       IDEXW(id, ex, 0)//没有操作数宽度
#define EXW(ex, w)         {NULL, concat(exec_, ex), w}//不用译码
#define EX(ex)             EXW(ex, 0)//只有执行函数
#define EMPTY              EX(inv)
```

首先在all-instr.h中声明call,push,sub,xor,pop,ret指令的执行函数make_EHelper(xxx)



##### push

根据手册，0x50-0x57均是push指令的op码，对应八个不同的通用寄存器。

译码函数：由于push的操作数均为寄存器，所以使用译码函数make_DHelper(r)，从op码中读取通用寄存器的编号，然后将寄存器的内容保存到id_dest->val中。

```c
make_DHelper(r) {
  //从op码中读取通用寄存器的编号，然后将寄存器的内容保存到id_dest->val中
  decode_op_r(eip, id_dest, true);
}
```

执行函数：首先实现push的rtl指令，esp-4，然后将要push的内容src1放入现在esp的位置。

```c
//push：esp-4，然后将要push的内容src1放入现在esp的位置
static inline void rtl_push(const rtlreg_t* src1) {
  // esp <- esp - 4
  // M[esp] <- src1
  //TODO();
  rtl_subi(&cpu.esp,&cpu.esp,4);
  rtl_sm(&cpu.esp,4,src1);
}
```

然后编写执行函数make_EHelper(push)

```c
make_EHelper(push) {
  //TODO();
  rtl_push(&id_dest->val);//之前在译码阶段将寄存器值保存到id_dest，现在将id_dest的值push进栈

  print_asm_template1(push);
}
```

最后修改operand_table

```c
  /* 0x50 */	IDEX(r,push), IDEX(r,push), IDEX(r,push), IDEX(r,push),
  /* 0x54 */	IDEX(r,push), IDEX(r,push), IDEX(r,push), IDEX(r,push),
```

##### pop

译码函数：make_DHelper(r)

rtl指令：

```c
//pop：将栈顶数据放入dest，然后esp+4
static inline void rtl_pop(rtlreg_t* dest) {
  // dest <- M[esp]
  // esp <- esp + 4
  //TODO();
  rtl_lm(dest,&cpu.esp,4);
  rtl_addi(&cpu.esp,&cpu.esp,4);
}
```

执行函数

```c
make_EHelper(pop) {
  //TODO();
  rtl_pop(&t0);//把栈顶元素保存在临时寄存器t0里面
  operand_write(id_dest, &t0);//保存到目标寄存器

  print_asm_template1(pop);
}
```

指令表：0x58-0x5f，但是因为0x5c对应的esp在rtl指令里要被用到，不能被修改，所以不包含0x5c

```c
  /* 0x58 */	IDEX(r,pop), IDEX(r,pop), IDEX(r,pop), IDEX(r,pop),
  /* 0x5c */	EMPTY, IDEX(r,pop), IDEX(r,pop), IDEX(r,pop),
```

##### call

call指令的操作数是一个有符号立即数，目的地址就是当前eip加上这个立即数

译码函数

```c
make_DHelper(J) {
  decode_op_SI(eip, id_dest, false);
  // the target address can be computed in the decode stage
  decoding.jmp_eip = id_dest->simm + *eip;//eip加立即数得到跳转地址
}
```

因为call指令的操作数是有符号立即数，所以之后要实现decode_op_SI，也就是make_DopHelper(SI)函数，si指的是有符号立即数

```c
//有符号立即数，宽度1字节或4字节
static inline make_DopHelper(SI) {
  assert(op->width == 1 || op->width == 4);//宽度1字节或4字节

  op->type = OP_TYPE_IMM;

  /* TODO: Use instr_fetch() to read `op->width' bytes of memory
   * pointed by `eip'. Interpret the result as a signed immediate,
   * and assign it to op->simm.
   * 
   op->simm = ???
   */
  //TODO();
  //从eip处读取op->width个字节的内存，并把结果转为有符号立即数，然后将它赋给op->simm
  op->simm = instr_fetch(eip, op->width);
  if(op->width==1){//宽为1字节，则转为8位有符号数
    op->simm = (int8_t)op->simm;
  }
  else{//宽为4字节，则转为32位有符号数
    op->simm = (int32_t)op->simm;
  }

  rtl_li(&op->val, op->simm);

#ifdef DEBUG
  snprintf(op->str, OP_STR_SIZE, "$0x%x", op->simm);
#endif
}
```

执行函数：control.c

```c
make_EHelper(call) {
  // the target address is calculated at the decode stage
  //TODO();
  //将当前eip（不是跳转地址）入栈
  rtl_li(&t0,decoding.seq_eip);
  rtl_push(&t0);
  decoding.is_jmp=1;//跳转标记
  print_asm("call %x",decoding.jmp_eip);
}
```

修改指令表

```c
 /* 0xe8 */ IDEX(J,call), EMPTY, EMPTY, EMPTY,
```

##### sub和eflags标志寄存器

为了实现sub指令的功能，首先需要定义eflags寄存器。eflags称为标志寄存器，其中有若干标志位，对于表示算数运算的结果状态有重要的作用：

- CF：**无符号**整型运算，若运算结果的最高有效位发生进位或借位则置1
- ZF：若结果为0则置1
- SF：结果的符号位，0为正，1为负
- IF：若屏蔽中断则置1
- OF：**有符号**数加减运算，发生溢出则置1

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\eflags.png" alt="eflags" style="zoom:67%;" />

根据上面的图示，我们在include/cpu/reg.h的CPU_state结构体里加入eflags寄存器的定义，其中未涉及到的标志位只留出了空间，并未定义。

```c
  //定义eflags寄存器，算术时用
  struct{
    uint32_t CF:1;
    unsigned:5;
    uint32_t ZF:1;
    uint32_t SF:1;
    unsigned:1;
    uint32_t IF:1;
    unsigned:1;
    uint32_t OF:1;
    unsigned:20;
  }eflags;
} CPU_state;
```

然后在src/monitor/monitor.c中对eflags初始化，设定eflags的初始值为0x0000 00002。

```c
//初始化寄存器
static inline void restart() {
  /* Set the initial instruction pointer. */
  cpu.eip = ENTRY_START;
  //设定eflags的初始值为0x0000 00002
  unsigned int init=2;
  memcpy(&cpu.eflags,&init,sizeof(cpu.eflags));
  
#ifdef DIFF_TEST
  init_qemu_reg();
#endif
}
```

添加各种rtl指令，使得ZF和SF标志位能够更新，封装后的rtl_update_ZFSF函数将在执行函数中使用。

```c
//更新eflags的各种标志位
//判断src是否为0
static inline void rtl_eq0(rtlreg_t* dest, const rtlreg_t* src1) {
  // dest <- (src1 == 0 ? 1 : 0)
  //TODO();
  rtl_sltui(dest,src,1);//如果src小于1（即=0），则dest置为1
}

//判断src和imm是否相等，即判断它俩异或是否为0
static inline void rtl_eqi(rtlreg_t* dest, const rtlreg_t* src1, int imm) {
  // dest <- (src1 == imm ? 1 : 0)
  //TODO();
  rtl_xori(dest,src1,imm);//dest=src^imm
  rtl_eq0(dest,dest);
}
//如果src不为0，返回1
static inline void rtl_neq0(rtlreg_t* dest, const rtlreg_t* src1) {
  // dest <- (src1 != 0 ? 1 : 0)
  //TODO();
  rtl_eq0(dest,src1);
  rtl_eq0(dest,dest);
}
//获得src1[width * 8 - 1]这一位
static inline void rtl_msb(rtlreg_t* dest, const rtlreg_t* src1, int width) {
  // dest <- src1[width * 8 - 1]
  //TODO();
  rtl_shri(dest,src1,width*8-1);//右移，直到最高位是需要的位
  rtl_andi(dest,dest,0x1);
}

static inline void rtl_update_ZF(const rtlreg_t* result, int width) {
  // eflags.ZF <- is_zero(result[width * 8 - 1 .. 0])
  //TODO();
  rtl_andi(&t0,result,(0xffffffffu>>(4-width)*8));//只获取result的后width字节
  rtl_eq0(&t0,&t0);
  rtl_set_ZF(&t0);
}
//符号位
static inline void rtl_update_SF(const rtlreg_t* result, int width) {
  // eflags.SF <- is_sign(result[width * 8 - 1 .. 0])
  //TODO();
  rtl_msb(&t0,result,width);
  rtl_set_SF(&t0);
}
static inline void rtl_update_ZFSF(const rtlreg_t* result, int width) {
  rtl_update_ZF(result, width);
  rtl_update_SF(result, width);
}
```

注意到还需要实现各种rtl_set_xx和rtl_get_xx函数的宏定义：

```c
#define make_rtl_setget_eflags(f) \
  static inline void concat(rtl_set_, f) (const rtlreg_t* src) { \
    cpu.eflags.f=*src; \
  } \
  static inline void concat(rtl_get_, f) (rtlreg_t* dest) { \
    *dest=cpu.eflags.f; \
  }
```

译码函数

```c
/* AL <- Ib
 * eAX <- Iv
 */
make_DHelper(I2a) {
  decode_op_a(eip, id_dest, true);//将eax寄存器的值保存至id_dest
  decode_op_I(eip, id_src, true);//将立即数保存至id_src
}
```

执行函数

在airth.c中定义eflags_modify函数计算减法，并更新eflags标志位。

```c
//计算减法，并更新eflags标志位
static inline void eflags_modify(){
  rtl_sub(&t2,&id->dest->val,&id_src->val);//dest-src结果存到t2
  //ZF和SF位
  rtl_update_ZFSF(&t2,id_dest->width);
  //CF：无符号数运算，如果被减数小于减数，则最高位需要借位，t0=1
  rtl_sltu(&t0,&id_dest->val,&id_src->val);
  rtl_set_CF(&t0);
  //OF：有符号数运算，看是否溢出。只有两种情况：正-负=负，负-正=正
  rtl_xor(&t0,&id->dest->val,&id_src->val);//两操作数是否异号
  rtl_xor(&t1,&id->dest->val,&t2);//运算结果和被减数是否异号
  rtl_and(&t0,&t0,&t1);//以上两个都为1才肯定溢出
  rtl_msb(&t0,&t0,id_dest->width);//取t0的最高位（符号位）
  rtl_set_OF(&t0);
}

make_EHelper(sub) {
  //TODO();
  eflags_modify();//减法结果在t2中
  operand_write(id_dest,&t2);//结果从t2写回dest
  print_asm_template2(sub);
}
```

opcode_table：

###### 备注：查手册可见0x29处为SUB Ev,Gv，所以填IDEX(G2E,sub)。

0x80,0x01,0x83处也是sub指令，但是需要opcode扩展。i386手册中sub指令在扩展opcode时，操作码后面有一个ModR/M字节，其中的reg/opcode字段被解释为扩展opcode，取值为digit=5，所以需要去opcode_table_gp1[5]处查找opcode_entry结构。

```c
  /* 0x28 */	EMPTY, IDEX(G2E,sub), EMPTY, IDEX(E2G,sub),  
  /* 0x2c */	EMPTY, IDEX(I2a,sub), EMPTY, EMPTY,
  /* 0x80 */	IDEXW(I2E, gp1, 1), IDEX(I2E, gp1), EMPTY, IDEX(SI2E, gp1),
/* 0x80, 0x81, 0x83 */
//opcode_table_gp1
make_group(gp1,
    EMPTY, EMPTY, EMPTY, EMPTY,
    EMPTY, EX(sub), EMPTY, EMPTY)
```

##### xor

执行函数：logic.c中

```c
make_EHelper(xor) {
  //TODO();
  rtl_xor(&t2,&id_dest->value,&id_src->value);
  operand_write(id_dest,&t2);
  //修改标志位
  //ZF和SF位
  rtl_update_ZFSF(&t2,id_dest->width);
  //CF和OF用不到，置零
  rtl_set_CF(&tzero);
  rtl_set_OF(&tzero);
  print_asm_template2(xor);
}
```

opcode_table：同样有opcode扩展，digit=6.

```c
  /* 0x30 */	IDEXW(G2E,xor,1), IDEX(G2E,xor), IDEXW(E2G,xor,1), IDEX(E2G,xor),
  /* 0x34 */	EMPTY, IDEX(I2a,xor), EMPTY, EMPTY,
/* 0x80, 0x81, 0x83 */
//opcode_table_gp1
make_group(gp1,
    EMPTY, EMPTY, EMPTY, EMPTY,
    EMPTY, EX(sub), EX(xor), EMPTY)
```

##### ret

ret的作用是返回到调用该函数的原地址处，即从栈中弹出原地址，再修改eip即可。

```c
control.c:
//ret要实现eip的返回，之前已经把原地址push进栈了
make_EHelper(ret) {
  //TODO();
  rtl_pop(&t2);//t2=栈顶
  decoding.jmp_eip=t2;
  decoding.is_jmp=1;
  print_asm("ret");
}

  /* 0xc0 */	IDEXW(gp2_Ib2E, gp2, 1), IDEX(gp2_Ib2E, gp2), EMPTY, EX(ret),
```
这样第一阶段就大功告成了。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\part1end.png" alt="part1end"  />

### 二、程序、运行时环境与AM

#### 1.编译执行and.c

(1) lea：将一个内存地址直接赋给目的操作数。data-mov.c中执行函数已经实现，查表8d处发现LEA Gv,M，所以在opcode表0x8d填IDEX(lea_M2G,lea)

leae=66的指令，其次指令10006a: xchg %ax, %ax什么也没做，所以相当于nop（opcode=90），故直接使用nop作为执行函数，在0x90处填EX(nop)，nop的执行函数在special.c中。

(3) pushl：压栈两个字

(4) xchg：交换两个寄存器的值。但是首先手册中xchg没有opcode=66的指令，其次指令10006a: xchg %ax, %ax什么也没做，所以相当于nop（opcode=90），故直接使用nop作为执行函数，在0x90处填EX(nop)，nop的执行函数在special.c中。

(5) add：arith.c

和sub一样，要设置标志位

```c
make_EHelper(add) {
  //TODO();
  rtl_add(&t2,&id_dest->val,&id_src->val);
  operand_write(id_dest,&t2);
  //ZF和SF位
  rtl_update_ZFSF(&t2,id_dest->width);
  //CF：无符号数运算，进位
  rtl_sltu(&t0,&t2,id_dest->val);//如果结果小于其中一个加数，肯定需要进位
  rtl_set_CF(&t0);
  //OF：有符号数运算，看是否溢出。只有两种情况：正+正=负，负+负=正，即结果和两个操作数都异号
  rtl_xor(&t0,&t2,id_dest->val);
  rtl_xor(&t1,&t2,id_src->val);
  rtl_and(&t0,&t0,&t1);//以上两个都为1才肯定溢出
  rtl_msb(&t0,&t0,id_dest->width);//取t0的最高位（符号位）
  rtl_set_OF(&t0);

  print_asm_template2(add);
}
```

(6) cmp：和sub完全一致，只不过不用保存结果

```c
make_EHelper(cmp) {
  //TODO();
  eflags_modify();//和sub完全一致
  print_asm_template2(cmp);
}
```

(7) setcc：cc代表condition code，有多种形式（例如0f 94 c0: sete %al），它作为一个测试的条件，需要根据eflags的各标志位来将操作数置为0或1

可以在logic.c中看到setcc的执行函数是将opcode的后4位作为subcode，再送到rtl_setcc进一步解析。

```c
make_EHelper(setcc) {
  uint8_t subcode = decoding.opcode & 0xf;
  rtl_setcc(&t2, subcode);
  operand_write(id_dest, &t2);

  print_asm("set%s %s", get_cc_name(subcode), id_dest->str);
}
```

在cc.c中，完成rtl_setcc函数。以case CC_LE为例，在i386手册的389页，可以看到：

```
0F 9F SETNLE r/m8 4/5 Set byte if not less or equal (ZF=1 and SF≠OF)
```

LE的意思就是less or equal，此时如果ZF=1 or SF≠OF，就将dest置为1.

```c
/* Condition Code */

void rtl_setcc(rtlreg_t* dest, uint8_t subcode) {
  bool invert = subcode & 0x1;//最低位
  enum {
    CC_O, CC_NO, CC_B,  CC_NB,
    CC_E, CC_NE, CC_BE, CC_NBE,
    CC_S, CC_NS, CC_P,  CC_NP,
    CC_L, CC_NL, CC_LE, CC_NLE
  };

  // TODO: Query EFLAGS to determine whether the condition code is satisfied.
  // dest <- ( cc is satisfied ? 1 : 0)
  switch (subcode & 0xe) {//与1110，取得倒数2-4位
    case CC_O:
      rtl_get_OF(dest);
      break;
    case CC_B:
      rtl_get_CF(dest);
      break;
    case CC_E:
      rtl_get_ZF(dest);
      break;
    case CC_BE:
      assert(dest!=&t0);
      rtl_get_CF(dest);
      rtl_get_ZF(&t0);
      rtl_or(dest,dest,&t0);
      break;
    case CC_S:
      rtl_get_SF(dest);
      break;
    case CC_L://SF==OF
      assert(dest!=&t0);
      rtl_get_SF(dest);
      rtl_get_OF(&t0);
      rtl_xor(dest,dest,&t0);
      break;
    case CC_LE://ZF==1 || SF!=OF
      //TODO();
      assert(dest!=&t0);
      rtl_get_SF(dest);
      rtl_get_OF(&t0);
      rtl_xor(dest,dest,&t0);
      rtl_get_ZF(&t0);
      rtl_or(dest,dest,&t0);
      break;
    default: panic("should not reach here");
    case CC_P: panic("n86 does not have PF");
  }

  if (invert) {
    rtl_xori(dest, dest, 0x1);
  }
}
```

注意手册中setcc指令的opcode有两个字节，所以译码和执行函数应该填在表2 byte_opcode_table中。

```c
  /*2 byte_opcode_table */
  /* 0x94 */	IDEXW(E,setcc,1), IDEXW(E,setcc,1), EMPTY, EMPTY,
  /* 0x98 */	EMPTY, EMPTY, EMPTY, EMPTY,
  /* 0x9c */	EMPTY, EMPTY, EMPTY, IDEXW(E,setcc,1),
```

(8) movzx和movsx：两字节opcode，x可被替代，例如movzbl

```c
  /* 0xb4 */	EMPTY, EMPTY, IDEXW(mov_E2G,movzx,1), IDEXW(mov_E2G,movzx,2),
  /* 0xb8 */	EMPTY, EMPTY, EMPTY, EMPTY,
  /* 0xbc */	EMPTY, EMPTY, IDEXW(mov_E2G,movsx,1), IDEXW(mov_E2G,movsx,2),
```

(9) test：两个操作数相与，根据结果设置eflags，不保存结果

```c
make_EHelper(test) {//两个操作数相与，根据结果设置eflags
  //TODO();
  rtl_and(&t2,&id_dest->val,&id_src->val);
  rtl_update_ZFSF(&t2,id_dest->width);
  //CF和OF用不到，置零
  rtl_set_CF(&tzero);
  rtl_set_OF(&tzero);
  print_asm_template2(test);
}
```

opcode要修改0x85和0xa8两处

(10) jmp：

```c
  /* 0xe8 */	IDEX(J,call), IDEX(J,jmp), EMPTY, IDEX(J,jmp,1),
```
这样就完成了and.c程序的执行。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\addend.png" alt="addend"  />

#### 2.编译执行其他c程序

之后，再将tests目录下其他所有c程序都执行一遍，完成其他的指令。因为代码量较为庞大，所以在这里我仅列出这些指令的功能。

右移sar, shr, 左移shl, not

自加inc, 自减dec, neg求补，按位取反+1

sbb:带借位减法指令，利用了CF位上记录的借位值

adc:带进位的加法指令

cltd:把eax的32位整数扩展为64位，高32位用eax的符号位填充保存到edx

leave：函数返回时，更新栈顶和栈底指针。将esp指向ebp，并将栈顶pop出来赋给ebp

call_rm：使用jmp_rm跳转

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\part2end.png" alt="part2end" style="zoom:80%;" />

#### 3.基础设施diff-test

diff-test是很好的debug工具，其本质是将nemu的输出和qemu对比，所以必须先安装qemu。

打开common.h中DIFF_TEST的宏定义，之后在exec_wrapper中，每执行一条指令后都要判断这些寄存器的值是否相同。

运行dummy程序，可以看到Connect to Qemu successfully：

![diff-test](C:\Users\Mika\Desktop\综合课程设计\pa2pic\diff-test.png)

##### runall和尝试debug

在nemu目录下使用bash runall.sh来进行所有样例测试。

在运行movsx.c时发现了hit bad trap，于是我编写了简化版的movsx2.c来debug：

![movsx2](C:\Users\Mika\Desktop\综合课程设计\pa2pic\movsx2.png)

![error](C:\Users\Mika\Desktop\综合课程设计\pa2pic\error.png)

运行后，发现在0x1000b0处nemu的eax值与qemu不同。进一步debug，发现0x100100处内存的值为0，而本应该是0x100128传给它的0x61，因此查找对应位置的反编译代码，发现是movsbl处出了问题。

查看movsbl的代码：

```c
make_EHelper(movsx) {
  id_dest->width = decoding.is_operand_size_16 ? 2 : 4;
  rtl_sext(&t2, &id_src->val, id_src->width);
  operand_write(id_dest, &t2);
  print_asm_template2(movsx);
}
```

movsbl的核心是符号扩展函数rtl_sext，检查sext函数发现确实有错误，修改后所有样例就都通过啦！

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\pass.png" alt="pass" style="zoom:80%;" />

第二阶段到此结束。

### 三、输入输出

IOE：输入输出扩展

端口映射I/O：CPU使用专门的I/O指令对设备进行访问，并把设备的地址称作端口号，作为io指令的一部分，缺点是I/O地址空间（所有能访问的设备的地址的集合）有限。

内存映射I/O：通过不同内存地址给设备编址，CPU通过普通的访存来访问设备。

注意：需要打开nemu/include/common.h中的HAS_IOE宏！

#### 串口

system.c，利用pio_read, pio_write函数来读写数据

使用in指令将设备寄存器的数据送到CPU寄存器；out指令将CPU寄存器的数据送到设备寄存器

```c
//in指令将设备寄存器的数据送到CPU寄存器
make_EHelper(in) {
  //TODO();
  //将数据从src读到dest
  rtl_li(&t0,pio_read(id_src->val,id_dest->width));
  operand_write(id_dest,&t0);

  print_asm_template2(in);

#ifdef DIFF_TEST
  diff_test_skip_qemu();
#endif
}
//out指令将CPU寄存器的数据送到设备寄存器
make_EHelper(out) {
  //TODO();

  pio_write(id_dest->val,id_src->width,id_src->val);
  print_asm_template2(out);

#ifdef DIFF_TEST
  diff_test_skip_qemu();
#endif
}
```

在 nexus-am/apps/hello目录下make run，即可输出10个Hello World!

#### 时钟

在nexus-am/am/arch/x86-nemu/src/ioe.c中定义_uptime函数，RTC_PORT是RTC寄存器的端口号，使用inl来访问该寄存器可以获得当前时间。

```c
//返回系统启动后经过的毫秒数
unsigned long _uptime() {
  return inl(RTC_PORT)-boot_time;
}
```

在nexus-am/tests/timetest运行`make ARCH=x86-nemu ALL=timetest run`，可以看到每隔一秒输出一行n seconds。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\seconds.png" alt="seconds" style="zoom:80%;" />

#### 3个benchmark跑分

dhrystone：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\dhrystone.png" alt="dhrystone" style="zoom:80%;" />

coremark：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\coremark.png" alt="coremark" style="zoom:80%;" />

microbench：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\microbench.png" alt="microbench" style="zoom: 80%;" />

#### 键盘

在keyboard.c中有如下宏定义：

#define I8042_DATA_PORT 0x60，是状态寄存器，判断是否为键盘io

#define I8042_STATUS_PORT 0x64，是数据寄存器，判断哪个键

通过\_read_key函数获得按键的键盘码，若无按键，则返回_KEY_NONE

```c
ioe.c:
//获得按键的键盘码，若无按键，则返回_KEY_NONE
int _read_key() {
  if(inb(0x64)){//状态寄存器，判断是否键盘io
    return inl(0x60);//读取数据寄存器，判断哪个键
  }
  else{
    return _KEY_NONE;
  }
}
```

运行keytest，可以看到按下和松开按键，nemu输出对应按键的up和down。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\key.png" alt="key" style="zoom:80%;" />

#### VGA

VGA (Video Graphics Array) 用于显示颜色像素。

mmio.c中定义了内存映射io表mmio_map，里面是每种io设备对应的内存信息。

is_mmio用来判断当前要访问的地址是否是内存映射io，是则返回映射号，否则返回-1

```c
/* bus interface */
//如果内存地址addr是内存映射io，则返回映射号
int is_mmio(paddr_t addr) {
  int i;
  for (i = 0; i < nr_map; i ++) {
    if (addr >= maps[i].low && addr <= maps[i].high) {
      return i;
    }
  }
  return -1;
}
```

memory.c中，对paddr_read和paddr_write加入了内存映射io的判断，利用is_mmio即可对io设备读写。

```c
/* Memory accessing interfaces */
//根据是否为内存映射io，决定读写主存方式
uint32_t paddr_read(paddr_t addr, int len) {
  int r=is_mmio(addr);
  if(r==-1){
    return pmem_rw(addr, uint32_t) & (~0u >> ((4 - len) << 3));
  }
  else{
    return mmio_read(addr,len,r);
  }
}

void paddr_write(paddr_t addr, int len, uint32_t data) {
  int r=is_mmio(addr);
  if(r==-1){
    memcpy(guest_to_host(addr), &data, len);
  }
  else{
    mmio_write(addr,len,data,r);
  }
}
```

运行videotest，可以看到如下画面：

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\videotest.png" alt="videotest" style="zoom: 67%;" />

但是这并非真正的videotest显示的画面，还需要实现ioe.c中_draw_rect函数：将pixels指定的矩形像素绘制到屏幕中以(x, y)和(x+w, y+h)两点连线为对角线的矩形区域。这样在运行程序甚至游戏时，就可以根据代码不断在屏幕上绘制需要的图像了！

注意内存中x是横轴（每个x是一列），y是纵轴（每个y是一行）

将像素数组pixels在内存的fb处存储即可输出具体的画面了。

```c
void _draw_rect(const uint32_t *pixels, int x, int y, int w, int h) {
  int minx=(w<_screen.width - x)?w:_screen.width - x;//x+w不能超过最大宽度
  int cp_bytes = sizeof(uint32_t) * minx;
  //对每一行
  for (int j = 0; j < h && y + j < _screen.height; j ++) {
    //y+j乘屏幕宽度+x列得到内存中y+j行的首地址
    memcpy(&fb[(y + j) * _screen.width + x], pixels, cp_bytes);//pixels是像素数组首地址
    pixels += w;
  }
}
```

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\video.png" alt="video" style="zoom: 67%;" />

进一步地，在apps/typing中可以运行打字游戏。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\typing.png" alt="typing" style="zoom:67%;" />

运行litenes（lite NES，红白机）玩马里奥，但是卡得不行。。。

<img src="C:\Users\Mika\Desktop\综合课程设计\pa2pic\mario.png" alt="mario" style="zoom:67%;" />

### 四、必答题

> 1.在 nemu/include/cpu/rtl.h 中,你会看到由 static inline 开头定义的各种 RTL 指令函数.选择其中一个函数,分别尝试去掉 static,去掉 inline 或去掉两者,然后重新进行编译,你会看到发生错误.请分别解释为什么会发生这些错误?你有办法证明你的想法吗? 

去掉static inline会导致该函数重定义，因为许多不同的c文件中都有该头文件。编译器编译时，每个c程序独立编译，所以该函数在每个可重定位目标文件（.o）的符号表中；而链接时会合并起来链接这些可重定位目标文件，所以会导致函数冲突。

去掉inline，函数会出现defined but not used的警告，因为inline本来使用时是直接嵌入的，去掉后就被当成了一个正常的函数，没有使用时就会警告。关掉werror就不会有警告了。

去掉static没有错误。

> 2.了解 Makefile 请描述你在 nemu 目录下敲入 make 后,make 程序如何组织.c 和.h 文件,最终生成可执行文件 nemu/build/nemu.(这个问题包括两个方面:Makefile 的工作方式和编译链接的过程.)

工作方式：首先读入主makefile，然后include其他引用的makefile，给变量初始化，使用隐含规则，为所有目标文件建立依赖关系链，决定哪些目标要重新生成，执行生成命令。

每条规则冒号右边是依赖的文件或目标，下面是指令。

```makefile
$(BINARY): $(OBJS)
	$(call git_commit, "compile")
	@echo + LD $@
	@$(LD) -O2 -o $@ $^ -lSDL2 -lreadline 
```

编译链接：首先将所有c文件编译成.o可重定位目标文件，然后打包链接生成可执行文件。