# win_pwdump
modified by quark_pwdump,compiled by mingw


quark_pwdump是开源查看windows 口令ntlm hash的利器，但是只支持vs编译,而且依赖jet(windows自带nosql库)，好像开源代码库中的依赖库也不全。
根据开发需要，把quark_pwdump本地查看windows口令hash的功能摘出来，并在mingw64编译通过。

环境：
ubuntu+mingw64

执行：
make

运行：
pwdump.exe + libcrypto-1_1-x64.dll + libssl-1_1-x64.dll (./libssl/bin)