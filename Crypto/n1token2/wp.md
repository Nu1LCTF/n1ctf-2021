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
