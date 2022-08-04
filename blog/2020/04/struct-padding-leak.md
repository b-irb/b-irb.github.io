- 2022-08-04
- Information Leakage With Struct Padding

Information leakage is a common auxiliary to execute an elaborate exploit. Process memory may contain secrets, such as: passwords, encryption keys, stack canaries, pointers to other data structures, etc. Consequently, allowing an attacker to leak process memory can have significant consequences. Typically, information leakage is the result of forcing an application to output uninitialised memory (considered UB in most, sane, languages).

An example of information leakage is as follows:

```c
#include <stdio.h>

int main() {
    char buf[16] = {'J', 'U', 'N', 'K', 'J', 'U', 'N', 'K',
                    'J', 'U', 'N', 'K', 'J', 'U', 'N', 'K'};
    char miscellaneous_stack_data[100] = "hunter2";

    fgets(buf, sizeof(buf), stdin);
    printf("%s\n", buf);
}
```

We allocate a buffer, `buf`, containing "junk bytes" (suppose these were leftover local variables from previous functions). Then we create a `miscellaneous_stack_data` buffer that contains a secret`. We attempt to place both buffers adjacently in memory.

```console
(gdb) p &buf
$1 = (char (*)[16]) 0x7fffffffdf30
(gdb) p &miscellaneous_stack_data
$2 = (char (*)[100]) 0x7fffffffdf40
```

Next, we attempt to read 16 bytes into `buf` with `fgets` then output the buffer to stdout. This looks fine but if we check the manpage for `fgets` we see:

> fgets() reads in at most one less than size characters from stream and stores
> them into the buffer pointed to by s. Reading stops after an EOF or a newline.
> If a newline is read, it is stored into the buffer. A terminating null byte
> ('\0') is stored after the last character in the buffer.

If we skim this description it looks fine, `fgets` will place a null terminator once it encounters a newline or if it reads `size` characters. However, if we read more carefully *Reading stops after an EOF*. By sending an EOF (ctrl+d on most Linux terminals), we realise `fgets` will not place a null terminator which allows us to leak the password.

```console
[user@beelzebub]: /tmp/tmp.zoum9Gc3En>$ gcc vuln.c -Wall -Wextra -pedantic -o vuln
vuln.c: In function ‘main’:
vuln.c:6:10: warning: unused variable ‘miscellaneous_stack_data’ [-Wunused-variable]
    6 |     char miscellaneous_stack_data[100] = "hunter2";
      |          ^~~~~~~~~~~~~~~~~~~~~~~~
[user@beelzebub]: /tmp/tmp.zoum9Gc3En>$ ./vuln
JUNKJUNKJUNKJUNKhunter2
```

We recieve no warnings or errors for our misuse of `fgets` but why would we? This behaviour is documented but commonly overlooked. From this example you ought to see how easy it is to accidentally leak process memory even with frequently used functions (to mitigate the above you should `memset` your buffer beforehand and ensure a null terminator is present).

Now, onto structs! A struct is a way in which we combine multiple heterogeneous datatypes into a single, coherent, structure. An example is shown below.

```c
struct _sigma16_cpu {
    sigma16_reg_t regs[16];
    union sigma16_inst_variant ir;
    sigma16_reg_t pc;
    sigma16_reg_t adr;
    sigma16_reg_t dat;
    sigma16_reg_status_t status;
    _Bool sys;
    _Bool ie;
    sigma16_reg_t mask;
    sigma16_reg_t req;
    sigma16_reg_status_t istat;
    sigma16_reg_t ipc;
    sigma16_reg_t vect;
}
```

The struct, `_sigma16_cpu` has several fields (e.g. `pc`, `adr`, `status`) which can be individually accessed. To improve performance, the C compiler will attempt to align the size of the struct to the size of the largest field. However, not all the datatypes have the same size (`assert(sizeof(char) == sizeof(int))` will fail) so to properly align the struct the compiler will insert padding bytes.

```c
#include <assert.h>

struct C {
    char x; /* 1 */
    int y;  /* 4 */
};

struct I {
    int x;  /* 4 */
    int y;  /* 4 */
};

int main() {
    struct C c = {.x = 'A', .y = 41};
    struct I i = {.x = 41, .y = 41};

    assert(sizeof(c) == sizeof(i));
}
```

In both structs, `int` is the largest data type which means both structs will attempt to align to it. However, `char` has a size of 1 so the compiler inserts 3 padding bytes, bringing the size of `struct C` to 8.

```console
[user@beelzebub]: /tmp/tmp.s3NX4aNGmq>$ gcc test.c -o test
[user@beelzebub]: /tmp/tmp.s3NX4aNGmq>$ ./test
[user@beelzebub]: /tmp/tmp.s3NX4aNGmq>$
```

As we can see, the assertion held. In other languages the fields of a struct may be reorganised to improve structure size by reducing the amount of padding bytes required.

```c
struct A {
    char x;
    int y;
    char z;
}; /* sizeof(struct A) == 12 */

struct B {
    char x;
    char z;
    int y;
}; /* sizeof(struct B) == 8 */
```

Despite having the same fields, `struct A` is larger than `struct B`. Although, if you want to remove padding entirely you can use `__attribute__((packed))`.

```c
__attribute__((packed)) struct A {
    char x;
    int y;
    char z;
}; /* sizeof(struct A) == 6 */
```

However, this is not a compiler directive and removing padding will make structures cache-unfriendly which will likely hamper performance.

How do padding bytes replate to information leakage? Padding bytes pare not _safely accessible in C and may contain arbitrary memory_. Places where this may occur is where we write a struct by doing `foo(&my_struct, sizeof(my_struct));` because you are including padding bytes. Instead, to write and read in structs, you should do it by individually accessing each field. An example application with an information leakage from struct padding is below.

```c
#include <crypt.h>
#include <stdio.h>
#include <string.h>

#define KEY_SIZE 16
#define SALT_SIZE 16

#define BLOWFISH 2

struct credentials {
    char salt[SALT_SIZE];
    char key[KEY_SIZE];
};

struct encrypted {
    unsigned char scheme;
    long long uid;
    unsigned char version;
};

char* read_user_creds(struct credentials* creds) {
    /* clear memory for null bytes */
    memset(creds->key, '\0', KEY_SIZE);
    memset(creds->salt, '\0', SALT_SIZE);

    fgets(creds->key, KEY_SIZE, stdin);
    fgets(creds->salt, SALT_SIZE, stdin);
}

char* encrypt_user_data(void) {
    struct credentials creds;
    read_user_creds(&creds);

    return crypt(creds.key, creds.salt);
}

int save_ciphertext_info(const char* fname) {
    static int uid = 0;

    struct encrypted blob = {.scheme = BLOWFISH, uid = uid++, .version = 0};
    FILE* save_file;

    if (!(save_file = fopen(fname, "wb"))) {
        return -1;
    }

    fwrite(&blob, sizeof(blob), 1, save_file);
    fclose(save_file);
}

int main() {
    char* encrypted;
    encrypted = encrypt_user_data();

    if (save_ciphertext_info("ciphertext_info.bin") < 0) {
        return -1;
    }
    printf("encrypted: %s\n", encrypted);
    return 0;
}
```

The application asks a user for their password and a salt to encrypt using `crypt`. Then the application emits the an encyption id, application version, and the encryption scheme.

```console
[user@beelzebub]: /tmp/tmp.eFj7oJofHA>$ gcc vuln.c -lcrypt -Wall -Wextra -pedantic -o vuln
[user@beelzebub]: /tmp/tmp.eFj7oJofHA>$ ./vuln
hunter2
s4lt
encrypted: s4Rw0kbw0ZFaU
[user@beelzebub]: /tmp/tmp.eFj7oJofHA>$ stat ciphertext_info.bin
  File: ciphertext_info.bin
  Size: 24        	Blocks: 8          IO Block: 4096   regular file
Device: 2dh/45d	Inode: 679587      Links: 1
Access: (0644/-rw-r--r--)  Uid: ( 1000/    user)   Gid: ( 1000/    user)
Access: 2020-04-19 22:46:08.728239131 +0100
Modify: 2020-04-19 22:46:27.114905573 +0100
Change: 2020-04-19 22:46:27.114905573 +0100
 Birth: -
[user@beelzebub]: /tmp/tmp.eFj7oJofHA>$ xxd ciphertext_info.bin
00000000: 0275 6e74 6572 320a 0000 0000 0000 0000  .unter2.........
00000010: 0000 0000 0000 0000                      ........
```

A chunk of the password is right there even though we wrote an unrelated piece of information to the file.

```c
int save_ciphertext_info(const char* fname) {
    static int uid = 0;

    struct encrypted blob = {.scheme = BLOWFISH, uid = uid++, .version = 0};
    FILE* save_file;

    if (!(save_file = fopen(fname, "wb"))) {
        return -1;
    }

    fwrite(&blob, sizeof(blob), 1, save_file);
    fclose(save_file);
}
```

Why does this work? Within the application, we allocate a struct on the stack which stores sensitive information. Then, we allocate another struct on the stack within a different function body. The struct padding of our second struct overlaps the `key` field of the `credentials` struct. When we write the entire struct to a file we also write this padding field, which includes part of our password. However, first byte is overwritten by the scheme.

We can inspect this overlapping by debugging the application.

```gdb
[user@beelzebub]: /tmp/tmp.eFj7oJofHA>$ gdb -q vuln
Reading symbols from vuln...
(gdb) disass encrypt_user_data
Dump of assembler code for function encrypt_user_data:
   0x000000000000121f <+0>:	push   rbp
   0x0000000000001220 <+1>:	mov    rbp,rsp
   0x0000000000001223 <+4>:	sub    rsp,0x30
   0x0000000000001227 <+8>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000001230 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001234 <+21>:	xor    eax,eax
   0x0000000000001236 <+23>:	lea    rax,[rbp-0x30]
   0x000000000000123a <+27>:	mov    rdi,rax
   0x000000000000123d <+30>:	call   0x11a9 <read_user_creds>
   0x0000000000001242 <+35>:	lea    rax,[rbp-0x30]
   0x0000000000001246 <+39>:	lea    rdx,[rbp-0x30]
   0x000000000000124a <+43>:	add    rdx,0x10
   0x000000000000124e <+47>:	mov    rsi,rax
   0x0000000000001251 <+50>:	mov    rdi,rdx
   0x0000000000001254 <+53>:	call   0x1070 <crypt@plt>
   0x0000000000001259 <+58>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000000125d <+62>:	xor    rcx,QWORD PTR fs:0x28
   0x0000000000001266 <+71>:	je     0x126d <encrypt_user_data+78>
   0x0000000000001268 <+73>:	call   0x1040 <__stack_chk_fail@plt>
   0x000000000000126d <+78>:	leave
   0x000000000000126e <+79>:	ret
End of assembler dump.
(gdb) b *encrypt_user_data+27
Breakpoint 1 at 0x123a: file vuln.c, line 32.
(gdb) r
Starting program: /tmp/tmp.eFj7oJofHA/vuln

Breakpoint 1, 0x000055555555523a in encrypt_user_data () at vuln.c:32
32	    read_user_creds(&creds);
(gdb) p &creds->key
$1 = (char (*)[16]) 0x7fffffffe0d0
(gdb) disass save_ciphertext_info
Dump of assembler code for function save_ciphertext_info:
   0x000055555555526f <+0>:	push   rbp
   0x0000555555555270 <+1>:	mov    rbp,rsp
   0x0000555555555273 <+4>:	sub    rsp,0x40
   0x0000555555555277 <+8>:	mov    QWORD PTR [rbp-0x38],rdi
   0x000055555555527b <+12>:	mov    rax,QWORD PTR fs:0x28
   0x0000555555555284 <+21>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000555555555288 <+25>:	xor    eax,eax
   0x000055555555528a <+27>:	mov    BYTE PTR [rbp-0x20],0x2
   0x000055555555528e <+31>:	mo    eax,DWORD PTR [rip+0x2de8]        # 0x55555555807c <uid.2508>
   0x0000555555555294 <+37>:	lea    edx,[rax+0x1]
   0x0000555555555297 <+40>:	mov    DWORD PTR [rip+0x2ddf],edx        # 0x55555555807c <uid.2508>
   0x000055555555529d <+46>:	cdqe
   0x000055555555529f <+48>:	mov    QWORD PTR [rbp-0x18],rax
   0x00005555555552a3 <+52>:	mov    BYTE PTR [rbp-0x10],0x0
   0x00005555555552a7 <+56>:	mov    rax,QWORD PTR [rbp-0x38]
   0x00005555555552ab <+60>:	lea    rsi,[rip+0xd52]        # 0x555555556004
   0x00005555555552b2 <+67>:	mov    rdi,rax
   0x00005555555552b5 <+70>:	call   0x555555555090 <fopen@plt>
   0x00005555555552ba <+75>:	mov    QWORD PTR [rbp-0x28],rax
   0x00005555555552be <+79>:	cmp    QWORD PTR [rbp-0x28],0x0
   0x00005555555552c3 <+84>:	jne    0x5555555552cc <save_ciphertext_info+93>
   0x00005555555552c5 <+86>:	mov    eax,0xffffffff
   0x00005555555552ca <+91>:	jmp    0x5555555552fa <save_ciphertext_info+139>
   0x00005555555552cc <+93>:	mov    rdx,QWORD PTR [rbp-0x28]
   0x00005555555552d0 <+97>:	lea    rax,[rbp-0x20]
   0x00005555555552d4 <+101>:	mov    rcx,rdx
   0x00005555555552d7 <+104>:	mov    edx,0x1
   0x00005555555552dc <+109>:	mov    esi,0x18
   0x00005555555552e1 <+114>:	mov    rdi,rax
   0x00005555555552e4 <+117>:	call   0x5555555550a0 <fwrite@plt>
   0x00005555555552e9 <+122>:	mov    rax,QWORD PTR [rbp-0x28]
   0x00005555555552ed <+126>:	mov    rdi,rax
   0x00005555555552f0 <+129>:	call   0x555555555030 <fclose@plt>
   0x00005555555552f5 <+134>:	mov    eax,0x0
   0x00005555555552fa <+139>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x00005555555552fe <+143>:	xor    rcx,QWORD PTR fs:0x28
   0x0000555555555307 <+152>:	je     0x55555555530e <save_ciphertext_info+159>
   0x0000555555555309 <+154>:	call   0x555555555040 <__stack_chk_fail@plt>
   0x000055555555530e <+159>:	leave
   0x000055555555530f <+160>:	ret
End of assembler dump.
(gdb) b *save_ciphertext_info+117
Breakpoint 2 at 0x5555555552e4: file vuln.c, line 46.
(gdb) c
Continuing.
hunter2
s4lt

Breakpoint 2, ...
46	    fwrite(&blob, sizeof(blob), 1, save_file);
(gdb) p &blob->scheme
$2 = (unsigned char *) 0x7fffffffe0d0 "\002unter2\n"
```

Here, gdb misinterpets the `unsigned char` datatype of `scheme` as a character array then dumps the "string". By looking at the address of each field we see both `&creds->key` and `&blob->scheme` are allocated at `0x7fffffffe0d0`.

While this example is contrived, it is important to consider. To mitigate this behaviour there are several approaches.

- Memset the entire struct before assigning values.

```c
struct encrypted blob;
memset(&blob, '\0', sizeof(blob));

blob.scheme = BLOWFISH;
blob.uid = uid++;
blob.version = 0;
```

- Write each field separately as mentioned previously.

```c
struct encrypted blob = {.scheme = BLOWFISH, uid = uid++, .version = 0};

/* snip */
fwrite(&blob->scheme, sizeof(blob.scheme), save_file);
fwrite(&blob->uid, sizeof(blob.uid), save_file);
fwrite(&blob->version, sizeof(blob.version), save_file);
```
