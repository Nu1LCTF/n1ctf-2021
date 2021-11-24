# n1token1

This task combines the traditional use of lattice reduction with the quadratic sieve factoring method.

First, we need to recover $c^2$ from these tokens. Let $x[i]$ be the product of those small primes. Since $c^2 / token_{i}^2=x_{i} \pmod{n}$ holds for all $i$ in range of 0 to 919 with $x[i]$ being 937bit at most, which is noticeably smaller than the 1024-bit modular n, a lattice can be constructed to compute $x[i]$, and then recover $c^2$.

With $c^2$ recovered, we can calculate $x[i]$ and factor them since they are very smooth. By doing this, we can get 920 equations in the following form. 
$$
token_i^2 \equiv prime_0^{A_{i,0}} \cdot prime_1^{A_{i,1}} \cdots prime_{919}^{A_{i,919}}\cdot c^2 \pmod{n}.
$$
A reasonable way to solve the problem is to eliminate $c^2$,or to deal with c after solving the linear system, but a more elegant way is considering $c^2$ as yet another "indivisible" prime and put it into the linear system as well. By calculating the basis of the left kernel matrix in GF(2) and multiplying all the corresponding equations together, a pair of (x,y) can be revealed, which satisfies both $x^2\equiv y^2 \pmod{n}$ and $x\neq \pm y \pmod{n}$. In other word,  $x\equiv y \pmod{p}$, but $x \equiv -y \pmod{q}$. This allows us to factor n by calculating GCD(x-y,n) and GCD(x+y,n), and finish the challenge easily.

~~~python
from Crypto.Util.number import *
token = []

with open("output.txt") as f:
    n = int(f.readline().strip("n = "))
    for i in range(920):
        token.append(int(f.readline().split(": ")[1]))

size = 20
B = matrix(ZZ,2*size-1,2*size-1)

for i in range(size):
    B[i,i] = 1
for i in range(size-1):
    B[0,size+i] = (token[i+1]*token[i+1]%n)<<1024
    B[i+1,size+i] = (-token[0]*token[0]%n)<<1024
    B[size+i,size+i] = n<<1024
C = B.LLL()

c2 = token[0]*token[0]*inverse(abs(C[0,0]),n)%n
A = matrix(ZZ,920,921)
primes = []

for i in range(920):
    x = token[i]*token[i]*inverse(c2,n)%n
    A[i, 920] = 1
    for j in range(len(primes)):
        while x%primes[j]==0:
            x = x//primes[j]
            A[i,j] += 1
    if x!=1:
        for j in sieve_base:
            if x%j==0:
                primes.append(j)
                while x%j==0:
                    x = x//j
                    A[i,len(primes)-1] += 1

A2 = matrix(GF(2),A)
res = A2.left_kernel().basis()

x = 1
y0 = vector(ZZ,921)
for i in range(920):
    if res[0][i]==1:
        x = x*token[i]%n
        y0 += vector(ZZ,A[i])

y = pow(c2,int(y0[920])//2,n)
for i in range(920):
    y = y*pow(primes[i],int(y0[i])//2,n)%n

y = int(y)
p = GCD(x-y,n)
q = GCD(x+y,n)

d = inverse(65537,int((p-1)*(q-1)))
m = int(pow(c2,d,n))**(1/2)
print(long_to_bytes(m))
~~~

