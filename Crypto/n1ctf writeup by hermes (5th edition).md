# Checkin

- Calculate the upper and lower bounds on $x$ based on the given higher 22 bits of $p$.

- Based on $h \equiv x + x^{-1} \pmod{n}$,  we can derive another equation $x^2-hx+1 \equiv 0 \pmod{n}$.

- Apply coppersmith's attack with $\epsilon = 0.02$, and run it for about a minute to recover $x$.
- Calculate $p$ and $q$ based on $x$ and $n$, and then decrypt the ciphertext to get flag.

~~~python
from Crypto.Util.number import *
n = 124592923216765837982528839202733339713655242872717311800329884147642320435241014134533341888832955643881019336863843062120984698416851559736918389766033534214383285754683751490292848191235308958825702189602212123282858416891155764271492033289942894367802529296453904254165606918649570613530838932164490341793
c = 119279592136391518960778700178474826421062018379899342254406783670889432182616590099071219538938202395671695005539485982613862823970622126945808954842683496637377151180225469409261800869161467402364879561554585345399947589618235872378329510108345004513054262809629917083343715270605155751457391599728436117833
h = 115812446451372389307840774747986196103012628652193338630796109042038320397499948364970459686079508388755154855414919871257982157430015224489195284512204803276307238226421244647463550637321174259849701618681565567468929295822889537962306471780258801529979716298619553323655541002084406217484482271693997457806
p0 = 4055618

lb = 2021*(p0<<490)+1120*n//(p0<<490)
ub = 2021*((p0+1)<<490)+1120*n//((p0+1)<<490)
print(int(ub-lb).bit_length())
PR.<x> = PolynomialRing(Zmod(n))
f = (x+lb)^2-h*(x+lb)+1
y = f.small_roots(X=ub-lb,epsilon=0.02)
s1 = int(y[0])+lb
s2 = (s1*s1-4*2021*1120*n)**(1/2)
p = (s1+s2)//4042
q = (s1-s2)//2240
d = inverse(65537,int((p-1)*(q-1)))
m = pow(c,d,n)
print(long_to_bytes(m))

~~~

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

## n1token2

We are given that 
$$
y(x) = e + c_0 \cdot x + c_1 \cdot x^2 + c_2 \cdot x^3 + ... + c_{15} \cdot x^{16} \pmod{p}
$$
Let 

$$
f(x) = c_{0} + c_{1} \cdot x + c_{2} \cdot x^2 + c_{3} \cdot x^3 + \cdots + c_{15} \cdot x^{15}\pmod{p}
$$
Then, the former equation can be rewritten as
$$
f(x)-(y(x)-e)/x \equiv 0 \pmod{p}
$$
Although the exact value of $e$ is unknown, we can narrow down its range of values to 5 choices as $e[i]$ where $i=0,1,2,3,4$. 

Denote $k[i] = (y(x)-e[i])/x$, so one of $f(x)-k[i] \equiv 0 \pmod{p}$ must holds.

Multiplying the 5 equations together, we can get the following equation.
$$
F = (f(x)-k[0])(f(x)-k[1])(f(x)-k[2])(f(x)-k[3])(f(x)-k[4])\equiv 0 \pmod{p}
$$

By expanding all the brackets, we can rewrite the equation as

$$
F[5]*f5(x)+F[4]*f4(x)+F[3]*f3(x)+F[2]*f2(x)+F[1]*f1(x) \equiv -F[0] \pmod{p}
$$
In the above equation, $fi(x)$, which is used to represent $(f(x))^i$, is a $15i$-th degree polynomial, and all of its $15i+1$ coefficients are independent of x. The five polynomials have a total of 76+61+46+31+16=230 unknown coefficients, and we have 250 tokens, so we can solve the coefficients by solving a system of linear equations.
~~~python
p = 251
y = bytes.fromhex('1d85d235d08dfa0f0593b1cfd41d3c98f2a542b2bf7a614c5d22ea787e326b4fd37cd6f68634d9bdf5f618605308d4bb16cb9b9190c0cb526e9b09533f19698b9be89b2e88ba00e80e44d6039d3c15555d780a6a2dbd14d8e57f1252334f16daef316ca692c02485684faee279d7bd926501c0872d01e62bc4d8baf55789b541358dfaa06d11528748534103a80c699a983c385e494a8612f4f124bd0b2747277182cec061c68197c5b105a22d9354be9e436c8393e3d2825e94f986a18bd6df9ab134168297c2e79eee5dc6ef15386b96b408b319f53b66c6e55b3b7d1a2a2930e9d34287b74799a59ab3f56a31ae3e9ffa73362e28f5751f79')
e = [1, 20, 113, 149, 219]

A = matrix(GF(p),250,230)
b = vector(GF(p),250)
PR.<f> = PolynomialRing(GF(p))
for i in range(250):
    F = 1
    for j in range(5):
        F = F*(f-GF(p)((y[i]-e[j])/(i+1)))
    for j in range(76):
        A[i,j] = F[5]*pow(i+1,j,p)
    for j in range(61):
        A[i,j+76] = F[4]*pow(i+1,j,p)
    for j in range(46):
        A[i,j+137] = F[3]*pow(i+1,j,p)
    for j in range(31):
        A[i,j+183] = F[2]*pow(i+1,j,p)
    for j in range(16):
        A[i,j+214] = F[1]*pow(i+1,j,p)
    b[i] = -F[0]
res = A.solve_right(b)
flag = 'n1ctf{' + bytes(res[214:]).hex() + '}'
print(flag)

~~~

