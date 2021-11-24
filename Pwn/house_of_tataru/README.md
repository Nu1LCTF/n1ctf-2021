## house\_of\_tataru

*step1* leak heap and pie by side channel

`musl` will reuse unused memory from `bss`. You can see more details in [kileak' writeup for this challenge](https://kileak.github.io/ctf/2021/n1ctf21-tataru/). So we can get chunk inside `bss`. But the pie and heap have random distance:

```
    0x564e3c891000     0x564e3c892000 r--p     1000 0      /pwn
    0x564e3c892000     0x564e3c893000 r-xp     1000 1000   /pwn
    0x564e3c893000     0x564e3c894000 r--p     1000 2000   /pwn
    0x564e3c894000     0x564e3c895000 r--p     1000 2000   /pwn
    0x564e3c895000     0x564e3c896000 rw-p     1000 3000   /pwn      <----chunk
      ^
      |
 random distance
      |
      v
    0x564e3d714000     0x564e3d715000 ---p     1000 0      [heap]
    0x564e3d715000     0x564e3d716000 rw-p     1000 0      [heap]
    0x7faf96450000     0x7faf96465000 r--p    15000 0      /lib/ld-musl-x86_64.so.1
    0x7faf96465000     0x7faf964cc000 r-xp    67000 15000  /lib/ld-musl-x86_64.so.1
    0x7faf964cc000     0x7faf96503000 r--p    37000 7c000  /lib/ld-musl-x86_64.so.1
    0x7faf96503000     0x7faf96504000 r--p     1000 b2000  /lib/ld-musl-x86_64.so.1
    0x7faf96504000     0x7faf96505000 rw-p     1000 b3000  /lib/ld-musl-x86_64.so.1

```

We can only know the heap address by leaking next `group's meta`. But how can we know the distance between pie and heap? In "edit" function, if `read` failed, it will print "fail" instead of crash, so we can use it to measure the distance. Then we can leak and write the meta region. Then we can leak libc by malloc a large chunk, which makes `musl` mmap a new memory above the libc. And it's `meta->mem` will point to it.

*step2* overwrite `__malloc_replaced` by "chunk offset"

Then we could overwrite meta region. And we can bypass the check in `calloc` by overwrite the `__malloc_replaced`:

```c
void *calloc(size_t m, size_t n)
{
	if (n && m > (size_t)-1/n) {
		errno = ENOMEM;
		return 0;
	}
	n *= m;
	void *p = malloc(n);
	if (!p || (!__malloc_replaced && __malloc_allzerop(p)))
		return p;
	n = mal0_clear(p, n);
	return memset(p, 0, n);
}
```

After Defcon 2021 qual, people like to overwrite memory in libc by unsafe unlink. But I find that in `enframe` in `malloc`, it will set the chunk's idx, if we can use it to overwrite the `__malloc_replaced`, we can bypass the check too. So I banned the unsafe unlink before `calloc`. After we overwrite the `__malloc_replaced`, we can get a arbitrary malloc by overwriting the  `meta->mem`.

*step3* overwrite head in __funcs_on_exit

in `exit`, it will call `__funcs_on_exit`:

```c
#define COUNT 32

static struct fl
{
	struct fl *next;
	void (*f[COUNT])(void *);
	void *a[COUNT];
} 
void __funcs_on_exit()
{
	void (*func)(void *), *arg;
	LOCK(lock);
	for (; head; head=head->next, slot=COUNT) while(slot-->0) {
		func = head->f[slot];
		arg = head->a[slot];
		UNLOCK(lock);
		func(arg);
		LOCK(lock);
	}
}
```

so we can overwrite the `head` pointer to a fake `fl struct` to control the rip. Then we can find a stack povit gadget `0x000000000007b1f5: mov rsp, qword ptr [rdi + 0x30]; jmp qword ptr [rdi + 0x38];` to ROP.

**unintended solution **

* The distance between pie and heap can be brute force, `r3kapig` costs 7hours to make it success remotely 😨
* ~~ overwrite  `meta->mem` to `bss` , and it can set a valid `group` to bypass the check in `calloc`. It's also a cool solution!~~

If we modify a "freed" `meta->mem`, then we can set a valid `group` through `alloc_group`, which will alloc a new group and set it's member. If we happen to be able to make the next allocated `group` the one we modified, we can bypass the check in the calloc. 

