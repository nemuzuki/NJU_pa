### PA1.开天辟地的篇章：最简单的计算机 实验报告

#### 一、实现正确的寄存器结构体

union联合：里面的元素共用一块内存，所以同时只能有一个元素有效。

```cpp
union node{
    int a;
    char b;
};
int main(){
    node n;
    n.a=12;
    n.b='a';
    cout<<n.a;
}
output:
97
```

匿名联合：如果在struct里面定义union，并且不给它在大括号后面命名，则称为一个匿名union。可以直接用union中成员的名字访问

EAX,EDX,ECX,EBX,EBP,ESI,EDI,ESP 是 32 位寄存器; AX,DX,CX,BX,BP,SI,DI,SP 是 16 位寄存器; AL,DL,CL,BL,AH,DH,CH,BH 是 8 位寄存器.还有一个32位程序计数器eip

但它们在物理上并不是相互独立的,例如 EAX 的 低16位是AX,而AX又分成AH和AL。如果想**实现这些内存的重叠**，就需要使用匿名union，也就是说这些成员本质上是一块内存，但是可以名字不同

在include/cpu/reg.h中定义寄存器结构体：

```cpp
typedef struct{
    union{
        union{
            uint32_t _32;
            uint16_t _16;
            uint8_t _8[2];
        }gpr[8];
        struct{
        	uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
        };
    };
    uint32_t eip;
}CPU_state;
```

For example, if we access cpu.gpr[3].\_16, we will get the `bx' register; if we access cpu.gpr[1]._8[1], we will get the 'ch' register.

因为按顺序ebx是第3个寄存器，而ebx的低16位是bx，所以用cpu.gpr[3].\_16表示bx；按顺序ecx是第1个，exc的低8~15位是ch，所以cpu.gpr[1]._8[1]表示ch

注意：union里面的eax,ecx等寄存器必须在一个匿名struct里面打包，否则会被当成使用同一内存！

NEMU由monitor监视器,CPU,memory,设备四个模块组成。

BIOS将用户程序从磁盘读入内存中0x100000处，然后让eip指向该位置。

nemu开始执行一个函数cpu_exec，里面循环执行exec_wrapper函数，该函数执行eip指向的指令，然后更新eip。cpu_exec传入参数-1，其补码实际上是最大整数0xffffff，这样保证了所有指令都被执行。

#### 二、基础设施:简易调试器

##### 1.解析命令

src/monitor/debug/ui.c中，定义指令的格式

比如nemu需要si指令，就仿照其他指令向cmd_table中添加内容，每一行分别是指令名称，帮助注释和函数名

```c
static struct {
  char *name;
  char *description;
  int (*handler) (char *);
} cmd_table [] = {//all commands
  { "help", "Display informations about all supported commands", cmd_help },
  { "c", "Continue the execution of the program", cmd_c },
  { "q", "Exit NEMU", cmd_q },

  /* TODO: Add more commands */

  { "si","Single step execute",cmd_si},
  { "info","Print values of all registers('r') or information of all watchpoints('w')",cmd_info},
  { "x","Print length [n] data from [addr] in memory",cmd_x},
  { "p","Calculate the value of an expression",cmd_p},
  { "w","add a watchpoint",cmd_w},
  { "d","delete a watchpoint",cmd_d},
};
```

##### 2.si：单步执行

利用sscanf(char *buffer,char *format,&argument)把buffer的内容按照format格式写入argument。这里的参数就是执行的指令数，然后执行对应数量的指令即可。

```c
static int cmd_si(char *args){
  int cnt=0;
  if(args==NULL){
    cnt=1;
  }
  else{
    sscanf(args,"%d",&cnt);//把args转为int型，赋给cnt
  }
  cpu_exec(cnt);
  return 0;
}
```

##### 3.info r：打印所有32位寄存器的值

参考include/cpu/reg.h中的定义，不同位数的寄存器使用不同的函数获取其中的值

```c
//打印寄存器的值 "info r"
static int cmd_info(char *args){
  if(args[0]=='r'){
    for(int i=R_EAX;i<=R_EDI;++i){
      printf("%s\t0x%x\n",regsl[i],reg_l(i));//32bit
    }
    printf("eip\t0x%08x\n",cpu.eip);
    for(int i=R_AX;i<=R_DI;++i){
      printf("%s\t0x%x\n",regsw[i],reg_w(i));//16bit
    }
    for(int i=R_AL;i<=R_BH;++i){
      printf("%s\t0x%x\n",regsb[i],reg_b(i));//8bit
    }
  return 0;
  }
  else if(args[0]=='w'){
    print_wp();
    return 0;
  }
  printf("error:args error in cmd_info\n");
  return 0;
}
```

##### 4.x 10 0x100000：打印0x100000某处及后面一共10个字的内存值

使用memory.c中的vaddr_read函数来获取内存中的数据。注意1个字是32位，所以迭代时地址以32为单位更新。

```c
//print memory data of 0x100000~0x100000+10* "x 10 0x100000"
static int cmd_x(char *args){
  if(args==NULL){
    printf("Error:need more arguments!");
    return 0;
  }
  int len,addr;
  sscanf(args,"%d%x",&len,&addr);
  for(int i=0;i<len;++i){
    printf("0x%x  0x%x\n",addr+32*i,vaddr_read(addr+32*i,32));
  }
  return 0;
}
```

![cmd_x](C:\Users\Mika\Desktop\综合课程设计\pa1pic\cmd_x.png)

#### 三、表达式求值

表达式求值的命令是p expr

##### 1.make_token：词法分析

首先，需要识别出表达式由哪些成分（token）组成，make_token函数完成这一任务，并将它们存到tokens数组中。其中词法分析需要用到正则表达式库<regex.h>，并在rules数组定义要用到的正则表达式。

注意：为了防止加号、乘号等被识别成正则表达式的闭包符号，需要前面加上转义字符。

```c
static struct rule {
  char *regex;
  int token_type;
} rules[] = {//add regular expression here

  /* TODO: Add more rules.
   * Pay attention to the precedence level of different rules.
   */

  {" +", TK_NOTYPE},    // spaces
  {"0x[0-9A-Fa-f]+",TK_HEX},
  {"0|[1-9][0-9]*",TK_NUM},
  {"\\$(eax|ecx|edx|ebx|esp|ebp|esi|edi|eip|ax|cx|dx|bx|sp|bp|si|di|al|cl|dl|bl|ah|ch|dh|bh)",TK_REG},
  {"\\+", '+'},         // plus
  {"-", '-'},
  {"\\*", '*'},
  {"\\/", '/'},
  {"\\(", '('},
  {"\\)", ')'},
  {"==", TK_EQ},         // equal
  {"!=",TK_NEQ},
  {"&&",TK_AND},
  {"\\|\\|",TK_OR},
  {"!",TK_NOT},
  {"-",TK_NEGA},//负号
  {"\\*",TK_DEREF},//指针解引用
};
```

make_token函数要在tokens里面存类型和值，对于不同类型的token有不同的处理方法。其中对于寄存器，如$eip，需要去掉$；对于十六进制数需要去掉0x。

```c
tokens[nr_token].type=rules[i].token_type;
switch(tokens[nr_token].type){
    case TK_NUM:
        strncpy(tokens[nr_token].str,substr_start,substr_len);
        *(tokens[nr_token].str+substr_len)='\0';//末尾加\0
        break;
    case TK_HEX://丢掉0x
        strncpy(tokens[nr_token].str,substr_start+2,substr_len-2);
        *(tokens[nr_token].str+substr_len)='\0';//末尾加\0
        break;
    case TK_REG://丢掉$
        strncpy(tokens[nr_token].str,substr_start+1,substr_len-1);
        *(tokens[nr_token].str+substr_len)='\0';//末尾加\0
        break;
}
```

注：str类型的函数中间加n具有安全性，因为有长度参数进行溢出限制。

##### 2.递归求值

在识别token之后，表达式计算的入口是eval函数。其内部首先用find_inferior_op函数找到最低优先级的运算符，然后分治去求运算符左右的表达式的值。

其中还有一个必要的步骤就是去掉表达式两边的括号（如果有的话），这就需要check_parentheses函数来进行括号检查，如果整个表达式被包在一对【可去的】括号里，就返回true。所以必须小心(1+2)*(3+4)的情况，直观的想法是判断有没有运算符在括号外面即可。

```c
//检查左右括号匹配，如果是(expr)类型，就返回true
//但是小心(1+2)*(3+4)的情况，即有运算符不在括号里，则返回false
bool check_parentheses(int l,int r){
  if(tokens[l].type!='(' || tokens[r].type!=')'){
    return false;
  }
  int cnt=0;
  for(int i=l;i<=r;++i){
    if(tokens[i].type=='(')cnt++;
    else if(tokens[i].type==')'){
      if(cnt>0)cnt--;
      else return false;
    }
    else if(cnt==0&&(tokens[i].type=='+'||tokens[i].type=='-'||tokens[i].type=='*'||tokens[i].type=='/'||tokens[i].type==TK_AND||tokens[i].type==TK_OR||tokens[i].type==TK_EQ||tokens[i].type==TK_NEQ)){
      return false;
    }
  }
  if(cnt==0)return true;
  return false;
}
```

在find_inferior_op函数中，优先级最低运算符肯定要从后往前找。关键的步骤就是定义运算符的优先级，我的定义方法是优先级越低值越大（我参考了一个完整的优先级表）。这里使用数组pos，pos[i]存首次出现优先级为i的位置，通过prior变量记录下来遇到的最大值，最后返回优先级编号最大的首次出现的位置即可。

```c
//寻找优先级最低的运算符，注意该运算是要最后执行的，因为接受的是递归分治的结果
int find_inferior_op(int l,int r){
  int in_parent=0;//首先肯定不在括号里
  int prior=0;
  int pos[20];//pos[i]存首次出现优先级为i的位置
  for(int i=0;i<20;++i)pos[i]=-1;//初始化

  //从右向左找
  for(int i=r;i>=l;--i){
    if(tokens[i].type==')'){
      in_parent=1;
    }
    else if(tokens[i].type=='('){
      in_parent=0;
    }
    else if(in_parent==0){
      //设定优先级，最后返回优先级值最大的位置
      if(tokens[i].type==TK_NEGA||tokens[i].type==TK_NOT||tokens[i].type==TK_DEREF){
        prior=max(prior,2);
        if(pos[2]==-1)pos[2]=i;
      }
      else if(tokens[i].type=='*'||tokens[i].type=='/'){
        prior=max(prior,3);
        if(pos[3]==-1)pos[3]=i;
      }
      else if(tokens[i].type=='+'||tokens[i].type=='-'){
        prior=max(prior,4);
        if(pos[4]==-1)pos[4]=i;
      }
		......
    }
  }
  //返回优先级编号最大的位置
  return pos[prior];
}
```

最后，就是计算表达式的接口eval函数了，主要分为三个部分：

- 对于单个token的处理
- 如果是(expr)形式，去括号
- 对含一个运算符的最小表达式，设定计算规则

```c
//表达式计算
int eval(int p,int q){
  if(p>q){
    return 0;
  }
  else if(check_parentheses(p,q)==true){//去掉expr左右括号，但是小心(1+2)*(3+4)的情况
    return eval(p+1,q-1);
  }
  else{
    //如果识别出负号，那么它右边的数肯定还没被识别，所以给右边乘个-1，一起返回即可
    if(tokens[p].type==TK_NEGA){
      return -eval(p+1,q);
    }
    else if(tokens[p].type==TK_DEREF){
      int addr=eval(p+1,q);//得到内存地址
      printf("%x\n",addr);
      int value=vaddr_read(addr,4);//访存4字节
      return value;
    }
    else if(tokens[p].type==TK_NOT){
      return !eval(p+1,q);
    }
    else if(tokens[p].type==TK_NUM){
      int value;
      char *str=tokens[p].str;
      sscanf(str,"%d",&value);
      return value;
    }
    else if(tokens[p].type==TK_HEX){
      int value;
      char *str=tokens[p].str;
      sscanf(str,"%x",&value);
      return value;
    }
	else if(tokens[p].type==TK_REG){
      //返回寄存器的值
      int i;
      for(i=0;i<8;++i){//32bit regs
        if(strcmp(tokens[p].str,regsl[i])==0)return reg_l(i);
        if(strcmp(tokens[p].str,regsw[i])==0)return reg_w(i);
        if(strcmp(tokens[p].str,regsb[i])==0)return reg_b(i);
      }
      if(strcmp(tokens[p].str,"eip")==0){
        return cpu.eip;
      }
      else {
        printf("error:TK_REG error in eval()\n");
        assert(0);
      }
    }

    int i=find_inferior_op(p,q);
    int left=eval(p,i-1),right=eval(i+1,q);
    switch (tokens[i].type)
    {
    case '+':return left+right;
    case '-':return left-right;
    case '*':return left*right;
    case '/':return left/right;
    case TK_NEGA:return right*(-1);
    case TK_AND:return left&&right;
    case TK_OR:return left||right;
    case TK_EQ:return left==right;
    case TK_NEQ:return left!=right;
    case TK_NOT:return !right;
    default:
      assert(0);
    }
  }
}
```

这样，在ui.c再写一个函数cmp_p调用这个接口，就可以进行表达式计算了。

另外，实验指导书要求了一些除了加减乘除外的运算，我也在上面的代码中实现。

还有一个要点就是实现负号和指针解引用。在词法分析后，需要遍历一遍识别出伪装成减号的负号。特征是：最开头或者（前面不是数或者右括号）。另外，因为在eval函数中分治是先左后右的，所以如果识别出负号，那么它右边的数肯定还没被识别，所以给右边的数乘个-1，一起返回即可。

指针解引用\*也是单目运算符，处理和负号基本一致，主要就是增加了一个根据地址访存的过程。

测试结果：

![表达式求值](C:\Users\Mika\Desktop\综合课程设计\pa1pic\表达式求值.png)

#### 四、监视点

监视点watchpoint是仿照gdb里的监视点实现的，它的作用是查看某个变量的值什么时候发生改变，改变时会停下来。

首先看看监视点的用法：配置makefile

```
run:
	g++ -g test.cpp -o test
	./test
gdb:
	gdb test
```

然后选定文件，开始运行到main函数，设置监视点

```
file test
start
watch expr
c
```

另外还有这些用法需要实现：

- 设置监视点：watch expr
- 输出监视点信息：info watch

- 运行直到监视点：c

- 删除监视点：d 编号

在watchpoint.c中，有一个数组wp_pool，作为监视点池存储所有空闲的监视点。head, free两个链表指针分别指向使用中、空闲的监视点。

> 注：在a.c中使用b.c文件中函数f的方法：
>
> 在a.c前面声明f，如果b.c中f是static的，则不能被其他文件调用！

1.new_wp：从free的头部弹出一个空闲的监视点，赋予其对应的表达式，并计算当前的值作为旧值。注意此时要将该监视点加入head链表的尾部

```c
//从free链表弹出一个空闲的监视点
bool new_wp(char *args){
  WP *res=free_;
  free_=free_->next;//更新free的头部为下一个节点
  res->NO=cnt++;
  res->next=NULL;
  strcpy(res->expr,args);//监视点对应的表达式
  bool success;
  res->old_value=expr(res->expr,&success);//计算表达式的值
  if(success==false){
    printf("error in new_wp:expr error\n");
    return false;
  }

  //res加入head链表的尾部
  WP *temp=head;
  if(temp==NULL){
    head=res;
  }
  else{
    while(temp->next){
      temp=temp->next;
    }
    temp->next=res;
  }
  printf("success set watchpoint %d, old value=%d\n",res->NO,res->old_value);
  return true;
}
```

2.free_wp：删除监视点，从head删除，归还到free链表头部

```c
//将索引为num的监视点从head删除，归还到free链表
bool free_wp(int num){
  WP *temp=head,*res=NULL;
  if(head==NULL){
    printf("no watchpoint\n");
    return false;
  }
  if(head->NO==num){
    head=head->next;
  }
  else{
    while(temp->next){
      if(temp->next->NO==num){
        res=temp->next;
        temp->next=temp->next->next;
        break;
      }
      temp=temp->next;
    }
  }
  //在free头部添加新节点
  if(res){
    res->next=free_;
    free_=res;
    return true;
  }
  return false;
}
```

3.print_wp：遍历head链表，打印正在忙的所有监视点信息

```c
//打印所有监视点信息
void print_wp(){
  if(head==NULL){
    printf("no watchpoint\n");
    return;
  }
  printf("watchpoint:\n");
  WP *temp=head;
  printf("NO.        expr        hitnums\n");
  while(temp){
    printf("%d        %s        %d\n",temp->NO,temp->expr,temp->hit_num);
    temp=temp->next;
  }
}
```

4.watch_wp：判断各表达式的值是否保持不变。如果表达式的值发生了变化就要输出旧值和新值，并且把旧值更新为新值。

```c
//各表达式的值是否保持不变
bool watch_wp(){
  bool success;
  if(head==NULL){
    return true;
  }
  WP *temp=head;
  int res;
  while(temp){
    //如果表达式的值发生了变化
    res=expr(temp->expr,&success);
    if(res!=temp->old_value){
      temp->hit_num++;
      printf("hardware watchpoint %d:%s\n",temp->NO,temp->expr);
      printf("old value:%d\nnew value:%d\n\n",temp->old_value,res);
      temp->old_value=res;//把旧值更新为新值
      return false;
    }
    temp=temp->next;
  }
  return true;
}
```

另外，监视点产生中断需要在cpu-exec.c中cpu_exec函数加上几行，即如果表达式的值变化，nemu需要改变状态停下来。

```c
#ifdef DEBUG
    /* TODO: check watchpoints here. */
    if(watch_wp()==false){//如果表达式的值变化，nemu需要停下来
      nemu_state=NEMU_STOP;
    }

#endif
```

测试结果：

![watchpoint](C:\Users\Mika\Desktop\综合课程设计\pa1pic\watchpoint.png)

#### 五、断点

中断由int指令（interrupt）产生，其中int 3指令表示该中断交给调试器debugger去处理，它有一个特殊的一字节操作码，用来替代任何指令的第一字节来产生一个断点。

当debugger需要OS继续运行程序时，在int 3处OS会发出一个信号，这个信号让debugger再次出现，把int 3指令替代成原本的指令，然后让指令指针指向上一条指令，因为当前的位置是刚才int 3的下一条指令。这时候程序仍在停止中，用户可以进行其他交互。

如果int 3指令变成了两个字节，则会发生错误。因为这可能会影响到原本的两条指令。

#### 六、必答题

1.查阅 i386 手册理解了科学查阅手册的方法之后,请你尝试在 i386 手册中查阅以下问题所在的位置,把需 要阅读的范围写到你的实验报告里面: 

（1）EFLAGS 寄存器中的 CF 位是什么意思? 

eflags寄存器是状态寄存器。cf位全称carry flag，当高位需要进位或借位时，cf位置1，否则为0.

（2）ModR/M 字节是什么? 

ModR/M字节包含三个信息字段：
mod字段，占据了字段的两个最高有效位字节，与r/m字段组合以形成32个可能的值：八个寄存器和24种索引模式；
reg字段，占mod后面的三位字段，指定寄存器号或操作码的另外三位信息。reg字段的含义由第一个决定
  指令的（操作码）字节；
r/m字段，它占该字段的三个最低有效位字节，可以指定一个寄存器作为操作数的位置，也可以形成寻址模式编码的一部分。

（3）mov 指令的具体格式是怎么样的?

![1](C:\Users\Mika\Desktop\综合课程设计\pa1pic\1.png)

![2](C:\Users\Mika\Desktop\综合课程设计\pa1pic\2.png)

2.shell 命令完成 PA1 的内容之后,nemu/目录下的所有.c 和.h 和文件总共有多少行代码?你是使用什么命 令得到这个结果的?和框架代码相比,你在PA1中编写了多少行代码?(Hint:目前2017分支中记录的正好是做PA1 之前的状态,思考一下应该如何回到"过去"?)你可以把这条命令写入 Makefile 中,随着实验进度的推进,你可以 很方便地统计工程的代码行数,例如敲入 make count 就会自动运行统计代码行数的命令.再来个难一点的,除去 空行之外,nemu/目录下的所有.c 和.h 文件总共有多少行代码? 

```
行数统计：find . -name "*.[ch]" |xargs cat|wc
不含空格的统计：find . -name "*.[ch]" |xargs cat|grep -v ^$|wc
查看分支：git branch
分支切换：git checkout pa0
```

pa0：3487行

![行数](C:\Users\Mika\Desktop\综合课程设计\pa1pic\pa0.png)

pa1：3874行，去掉空行后3161行。

![行数](C:\Users\Mika\Desktop\综合课程设计\pa1pic\行数.png)



3.使用 man 打开工程目录下的 Makefile 文件,你会在 CFLAGS 变量中看到 gcc 的一些编译选项.请解释 gcc 中的-Wall 和-Werror 有什么作用?为什么要使用-Wall 和-Werror?

-Wall：开启所有警告，可以避免编译器自动适应一些看不见的错误。

-Werror：将警告作为错误。

#### *七、一些自用注意事项

设置root密码：sudo passwd

重装系统后，想再进行实验（make run）：

```
首先git checkout pa0
make run
然后git checkout pa1
make run
```

分支切换后，如果有修改再切回来，需要：

```
git add.
git commit -m "commit message"
切换到分支pa1：git checkout pa1

创建分支pa2：git branch pa2
查看所有分支：git branch
```

在主目录下make submit打包

gcc同时编译多个文件

```
gcc main.c test.c -o main
```

