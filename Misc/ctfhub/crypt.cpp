#include<bitset>
#include<iostream>
using namespace std;
typedef unsigned char u8;
typedef unsigned int u32;
const u8 ptbl[]={32,22,30,38,28,37,26,5,12,3,20,0,31,39,18,43,11,6,17,23,36,24,14,33,47,41,7,40,44,35,34,42,9,4,16,21,1,29,13,46,10,8,15,27,45,25,19,2};
const u8 p2tbl[]={47,28,34,48,0,43,9,25,30,18,62,55,36,24,11,52,38,5,37,35,60,15,42,21,40,53,33,27,32,58,3,19,10,16,29,20,50,12,59,13,49,54,63,1,46,57,39,61,31,17,6,14,56,2,7,41,51,8,26,45,4,22,44,23};
const u8 sbox[]={15,6,1,12,4,7,14,3,9,11,2,5,8,0,10,13,9,7,15,4,8,13,14,11,3,2,5,0,6,1,12,10,13,1,12,8,0,3,14,4,7,15,2,9,5,10,11,6,4,12,11,9,8,10,0,7,13,1,15,14,6,3,5,2,10,1,8,13,7,5,4,11,3,15,9,2,0,14,12,6,11,0,2,8,10,12,13,4,1,3,6,5,15,14,7,9,5,10,8,6,3,12,13,4,11,7,0,1,15,14,9,2,8,3,10,7,2,15,11,5,4,13,6,12,0,14,9,1,0,1,11,5,9,3,2,14,10,7,8,4,15,13,12,6,5,9,8,11,6,13,3,15,12,0,2,4,7,1,10,14,10,9,5,0,2,13,6,8,11,1,3,14,15,12,4,7,12,4,13,5,6,1,14,8,11,3,0,9,15,10,2,7,2,3,12,14,7,9,11,4,13,15,5,8,6,0,10,1,7,5,10,2,14,11,15,13,3,12,6,0,8,4,1,9,1,11,12,13,0,5,2,10,14,9,15,7,8,3,6,4,2,12,7,9,13,8,6,4,11,14,5,0,15,10,1,3,13,15,7,10,6,3,8,11,4,1,0,14,2,12,5,9,8,5,2,3,0,6,12,10,13,1,15,7,11,14,4,9,10,14,0,15,6,4,1,2,7,3,5,13,8,12,9,11,13,14,9,10,2,3,15,6,7,4,11,5,12,0,8,1,13,5,2,15,10,14,1,7,6,9,8,11,4,12,0,3,0,15,1,12,11,9,13,5,3,8,10,6,2,14,7,4,13,8,2,5,14,15,12,11,3,0,9,6,7,10,1,4,9,3,14,8,2,13,4,11,10,12,15,7,0,1,6,5,10,14,8,12,1,11,0,5,7,15,3,4,13,9,2,6,3,9,12,5,1,11,2,4,10,8,7,6,13,14,15,0,14,13,6,7,9,12,3,2,1,10,11,5,0,15,4,8,3,10,0,2,15,6,12,4,13,14,8,11,1,9,5,7,1,10,12,3,6,8,14,2,4,5,11,0,7,9,15,13,6,11,7,8,12,10,4,5,9,13,3,2,15,14,1,0,7,1,12,2,6,9,4,0,14,8,13,3,10,5,15,11,5,10,11,14,4,7,8,6,1,3,9,12,0,2,13,15};
#define range(i,n) for(int (i)=0;(i)<(n);++(i))
#define _EXPORT __attribute__((visibility ("default")))
#define _OPTIFUNC __attribute__((const)) inline static
_OPTIFUNC bitset<48> e(bitset<32> s){
    bitset<48> res;
    range(i,32){
        res[i]=s[i];
    }
    range(i,16){
        res[32+i]=s[i<<1]^s[1+(i<<1)];
    }
    return res;
}
template<int X>
_OPTIFUNC bitset<X> p(bitset<X> inp,const u8* tbl){
    bitset<X> res;
    range(i,X){
        res[i]=inp[tbl[i]];
    }
    return res;
}
template<int X>
_OPTIFUNC bitset<X> ip(bitset<X> inp,const u8* tbl){
    bitset<X> res;
    range(i,X){
        res[tbl[i]]=inp[i];
    }
    return res;
}
_OPTIFUNC bitset<32> sboxpass(bitset<48> inp){
    u8 res[4];
    range(i,8){
        u32 k1=sbox[i*64+((inp>>(i*6))&bitset<48>{0b111111}).to_ulong()];
        i++;
        u32 k2=sbox[i*64+((inp>>(i*6))&bitset<48>{0b111111}).to_ulong()];
        res[i>>1]=((k2<<4)|k1);
    }
    return {*(unsigned int*)res};
}
_OPTIFUNC bitset<32> f(bitset<32> x,bitset<48> k){
    auto x1=e(x);
    x1=p<48>(x1,ptbl);
    x1^=k;
    return sboxpass(x1);
}
_OPTIFUNC bitset<48> getk(bitset<64> k,int rnd){
    range(i,rnd){
        k=ip<64>(k,p2tbl);   
    }
    return {k.to_ullong()};
}
const u8 k[]={123,87,24,249,207,81,114,215};
const char plain[]="aabbccdd";
_OPTIFUNC bitset<64> encblock(bitset<64> inp,bitset<64> key,bitset<64> iv){
  inp^=iv;
  inp=p<64>(inp,p2tbl);
  bitset<32> l{inp.to_ullong()&0xffffffff},r{inp.to_ullong()>>32};
  //range(i,3){
    auto l1=r;
    auto r1=l^f(r, getk(key,0));
    l=l1,r=r1;
    l1=r;
    r1=l^f(r, getk(key,1));
    l=l1,r=r1;
    l1=r;
    r1=l^f(r, getk(key,2));
    l=l1,r=r1;
  //}
  bitset<64> res{(r.to_ullong()<<32)|l.to_ullong()};
  return ip<64>(res,p2tbl);
}
_OPTIFUNC bitset<64> decblock(bitset<64> inp,bitset<64> key,bitset<64> iv){
  inp=p<64>(inp,p2tbl);
  bitset<32> l{inp.to_ullong()&0xffffffff},r{inp.to_ullong()>>32};
  //range(i,3){
  auto l1=r^f(l, getk(key,2));
  auto r1=l;
  l=l1,r=r1;
  l1=r^f(l, getk(key,1));
  r1=l;
  l=l1,r=r1;
  l1=r^f(l, getk(key,0));
  r1=l;
  l=l1,r=r1;
  //}
  bitset<64> res{(r.to_ullong()<<32)|l.to_ullong()};
  return ip<64>(res,p2tbl)^iv;
}
extern "C" {
_EXPORT void encrypt(unsigned long long *payload, unsigned int blks, unsigned long long key,
             unsigned long long *out);
_EXPORT void decrypt(unsigned long long *payload, unsigned int blks, unsigned long long key,
                                                    unsigned long long *out);
}
extern "C" {
_EXPORT void encrypt(unsigned long long *payload, unsigned int blks, unsigned long long key,
             unsigned long long *out) {
if(blks>300) return;
  bitset<64> iv;
  range(i, blks) {
    bitset<64> last = encblock({*payload}, {key}, iv);
    *out = last.to_ullong();
    ++out;
    ++payload;
    iv = last;
  }
}
_EXPORT void decrypt(unsigned long long *payload, unsigned int blks, unsigned long long key,
                                                  unsigned long long *out) {
if(blks>300) return;
  bitset<64> iv;
  range(i, blks) {
    bitset<64> last = decblock({*payload}, {key}, iv);
    iv={*payload};
    *out = last.to_ullong();
    ++out;
    ++payload;
  }
}
}
