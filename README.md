# hbp_attack demo

参考P0博客：https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html



搓了个vuln module，假装我们有个内核任意地址写的原语，但开了kaslr暂时没有地址泄露。

于是可以借助`cpu_entry_area`不参与kaslr随机化的特性和硬件断点可以在内核态触发的特性，完成内核栈上kaslr和canary的泄露并通过ROP攻击提权。

思路我有点懒的写，建议直接看原文和代码（有机会应该会补）。



![](success.png)