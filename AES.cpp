using namespace std;
#include <iostream>
#include<iomanip>

//密钥拓展
uint32_t *KeyExpansions(uint32_t[]);
uint32_t T(uint32_t,int);

//轮密钥加
uint32_t *AddRoundKey(uint32_t[],uint32_t[]);

//字节代换
uint32_t *SubBytes(uint32_t[]);

//行移位
uint32_t *ShiftRows(uint32_t[]);

//列混淆
uint32_t *MixColumns(uint32_t[]);

//二进制乘法*2，*3
uint8_t BinMult(uint8_t,uint8_t);

//AES
uint32_t *AES(uint32_t[],uint32_t[]);


uint8_t S_BOX[256]={
    // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f
	uint32_t Rcon[10]={
		0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1B000000,0x36000000
	};

uint8_t P[16],key[16];

//字节代换
uint32_t *SubBytes(uint32_t s[4]){
	uint32_t *ss=new uint32_t[4];
	for(int i=0;i<4;i++){
		uint32_t temp0,temp=s[i] ;
		uint8_t temp1 = (0xff000000 & temp)>>24;		
		temp1=S_BOX[(temp1 >> 4)*16+(temp1 & 0x0f)];
		temp0 = temp1<<24;
		uint8_t temp2 =(0x00ff0000 & temp)>>16;				
		temp2=S_BOX[(temp2 >> 4)*16+(temp2 & 0x0f)];		
		temp0 = temp0 + (temp2<<16);		
		uint8_t temp3 =(0x0000ff00 & temp)>>8;		
		temp3=S_BOX[(temp3 >> 4)*16+(temp3 & 0x0f)];		
		temp0 = temp0 + (temp3<<8);		
		uint8_t temp4 =(0x000000ff &temp);
		temp4 =S_BOX[(temp4 >>4)*16+(temp4 & 0x0f)];		
		temp0 =temp0 + temp4 ;
		ss[i]=temp0;
	}
	return  ss;
}
uint32_t SubBytesmin(uint32_t temp){
	uint32_t temp0;
	uint8_t temp1 = (0xff000000 & temp)>>24;		
	temp1=S_BOX[(temp1 >> 4)*16+(temp1 & 0x0f)];
	temp0 = temp1<<24;
	uint8_t temp2 =(0x00ff0000 & temp)>>16;				
	temp2=S_BOX[(temp2 >> 4)*16+(temp2 & 0x0f)];		
	temp0 = temp0 + (temp2<<16);		
	uint8_t temp3 =(0x0000ff00 & temp)>>8;			
	temp3=S_BOX[(temp3 >> 4)*16+(temp3 & 0x0f)];		
	temp0 = temp0 + (temp3<<8);		
	uint8_t temp4 =(0x000000ff &temp);
	temp4 =S_BOX[(temp4 >>4)*16+(temp4 & 0x0f)];		
	temp0 =temp0 + temp4 ;
	return temp0;
}		
		
//密钥拓展
uint32_t *KeyExpansions(uint32_t key[4]){
	uint32_t *ekey =new uint32_t[44];
	for(int i=0;i<4;i++){
		ekey[i]=key[i];
	}
	for(int i=4;i<44;i++){
		if((i%4)!=0){
			ekey[i]=ekey[i-4]^ekey[i-1];
		}
		else 
		{
			ekey[i]=ekey[i-4]^T(ekey[i-1],i/4);
		}
	}
	
	return ekey;
	}
uint32_t T(uint32_t key0,int num)
{
	uint32_t keyt;
	keyt = (key0<<8) | (key0>>24);
	keyt = SubBytesmin(keyt);
	keyt = keyt ^ Rcon[num-1];
	return keyt;
}


//轮密钥加

uint32_t *AddRoundKey(uint32_t key[4],uint32_t s[4]){
	uint32_t *s1 =new uint32_t[4];
	for(int i=0;i<4;i++){
		s1[i]=key[i]^s[i];
	}
	return s1;

}
//行移位
uint32_t *ShiftRows(uint32_t s[4]){
	uint32_t *ss= new uint32_t[4];
	for(int i=0;i<4;i++){
		ss[i]= (s[i] & 0xff000000) +(s[(i+1)%4] & 0x00ff0000)+(s[(i+2)%4] & 0x0000ff00)+(s[(i+3)%4] & 0x000000ff);
	}
	return ss;
}
//列混合
uint32_t *MixColumns(uint32_t s[4]){
	uint32_t *ss=new uint32_t[4]; 
	for(int i=0;i<4;i++){
		uint8_t temp0 = (s[i] & 0xff000000)>>24;
		uint8_t temp1 = (s[i] & 0x00ff0000)>>16;
		uint8_t temp2 = (s[i] & 0x0000ff00)>>8;
		uint8_t temp3 = (s[i] & 0x000000ff);
		uint32_t sstemp0 = BinMult(2,temp0)^BinMult(3,temp1)^temp2^temp3;
		uint32_t sstemp1 = temp0^BinMult(2,temp1)^BinMult(3,temp2)^temp3;
		uint32_t sstemp2 = temp0^temp1^BinMult(2,temp2)^BinMult(3,temp3);
		uint32_t sstemp3 = BinMult(3,temp0)^temp1^temp2^BinMult(2,temp3);
		ss[i]= (sstemp0 <<24)+(sstemp1<<16)+(sstemp2 <<8)+sstemp3;
	}
	return ss;
}
//二进制乘法*2,*3
uint8_t BinMult(uint8_t a,uint8_t b){
	uint8_t r;
	int c=b;
	if(a==2){
		b=b<<1;
		if((c & 0x80)==0){
			r=b;
		}
		else{
			r=b^0b00011011;
		}

	}
	if(a==3){
		r=BinMult(2,b)^b;
	}
	return r;

}


uint32_t *AES(uint32_t p[4],uint32_t k[4]){
	uint32_t *c =new uint32_t[4];
	uint32_t *s =new uint32_t[4];
	uint32_t *key = KeyExpansions(k);

	s = AddRoundKey(k,p);
	
	
	for(int i=1;i<10;i++){
		uint32_t keyi[4];
		s=SubBytes(s);
		

		s=ShiftRows(s);
		

		s=MixColumns(s);
		


		for(int j=0;j<4;j++){
			keyi[j]=key[i*4+j];
		}
		


		s=AddRoundKey(keyi,s);
		
	}
	s=SubBytes(s);

	s=ShiftRows(s);
	
	uint32_t key11[4];

	for(int i=0;i<4;i++){
		key11[i]=key[40+i];
	}
	s=AddRoundKey(key11,s);
	
c=s;
return c;

}
int main(){
	uint32_t p[4] = {0x00112233,0x44556677,0x8899aabb,0xccddeeff};
	uint32_t k[4] = {0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f};
	uint32_t *c=AES(p,k);
	cout<<"The ciphertext is: "<<endl;
	for(int i=0;i<4;i++){
	
		cout<<hex<<setw(8)<<setfill('0')<<c[i];
	}
	cout<<endl;
	system("pause");
}
