# babyFMT

In this challenge ,I rewrote simple scanf and printf functions.And there is no vulnerability in other functions.

## babyscanf

Only %d and %s can be used，and it works like normal scanf.

## babyprintf

In this funtion, the format string is no longer %d and %s but %m and %r.

%m is like %d and %r is like %s.

After analyzing, you can find that there is a buf to save the string which was modified.And the size of the buf depends on the user input.

First,size is the length of user input

```c
  v10 = strlen(a1);
  v11 = *a1;
  size = v10;
```

Next, I traverse the entire string,and add 0x10 to the size of buf as long as finding a '%'.The goal of it is to avoid overflow when the string is modified blow.

But ,when you input '%x'(x could be any character except 'm' and 'r') ,it will execute the code below.

```c
default:
          v19 = v43;
          v20 = 0;
          if ( v9[1] )
          {
            do
            {
              *v19++ = v18 % 10 + 48;
              v18 /= 10;
              v21 = v20++;
            }
            while ( v18 );
            v22 = v21;
            v23 = &v43[v21];
            v24 = (__int64)v17->m128i_i64 + v22 + 1;
            v25 = v17;
            do
            {
              v26 = *v23;
              v25 = (__m128i *)((char *)v25 + 1);
              --v23;
              v25[-1].m128i_i8[15] = v26;
            }
            while ( v25 != (__m128i *)v24 );
LABEL_21:
            v17 = (__m128i *)((char *)v17 + v20);
          }
```

This code just avoid the character after '%', convert it to the ASCII number.

So, when the input is '%\x00xxxxxxxxxxxxx',the size of the buf will be 0x11.But the characters after \x00 will still be put at the end.

Now, a heap overflow is found.You just need to use show function to leak libc address, and modify the next pointer of tcache bins to set __free_hook to system.

Then show('/bin/sh\x00') will give you a shell.



