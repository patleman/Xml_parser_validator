#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<inttypes.h>

using namespace std;

#define WORD_SIZE 4

#define BN_ARRAY_SIZE    ((256 / WORD_SIZE) + 1)



#define DTYPE                    uint32_t
#define DTYPE_TMP                uint64_t
#define DTYPE_MSB                ((DTYPE_TMP)(0x80000000))
#define SPRINTF_FORMAT_STR       "%.08x"
#define SSCANF_FORMAT_STR        "%8x"
#define MAX_VAL                  ((DTYPE_TMP)0xFFFFFFFF)


/* Custom assert macro - easy to disable */
//#define require(p, msg) assert(p && #msg)

/* Data-holding structure: array of DTYPEs */
struct bn
{
  DTYPE array[BN_ARRAY_SIZE];
};

/* Tokens returned by bignum_cmp() for value comparison */
enum { SMALLER = -1, EQUAL = 0, LARGER = 1 };

static const char *const BASE64_DIGITS ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char *const HEX_DIGITS = "0123456789abcdef";

class SHA256 {

public:
	SHA256();
	void update(uint8_t * data, size_t length);
	uint8_t * digest();
  

private:
	uint8_t  m_data[64];
	uint32_t m_blocklen;
	uint64_t m_bitlen;
	uint32_t m_state[8]; //A, B, C, D, E, F, G, H

    uint32_t K[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
		0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
		0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
		0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
		0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
		0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
		0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
		0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
		0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	static uint32_t rotr(uint32_t x, uint32_t n);
	static uint32_t choose(uint32_t e, uint32_t f, uint32_t g);
	static uint32_t majority(uint32_t a, uint32_t b, uint32_t c);
	static uint32_t sig0(uint32_t x);
	static uint32_t sig1(uint32_t x);
	void transform();
	void pad();
	void revert(uint8_t * hash);
	
};

SHA256::SHA256(): m_blocklen(0), m_bitlen(0) {
	m_state[0] = 0x6a09e667;
	m_state[1] = 0xbb67ae85;
	m_state[2] = 0x3c6ef372;
	m_state[3] = 0xa54ff53a;
	m_state[4] = 0x510e527f;
	m_state[5] = 0x9b05688c;
	m_state[6] = 0x1f83d9ab;
	m_state[7] = 0x5be0cd19;
}
void SHA256::update( uint8_t * data, size_t length) {
	for (size_t i = 0 ; i < length ; i++) {
		m_data[m_blocklen++] = data[i];
	   // printf("%c",data[i]);
		if (m_blocklen == 64) {
			transform();

			// End of the block
			m_bitlen += 512;
			m_blocklen = 0;
		}
	}
}

uint8_t * SHA256::digest() {
	uint8_t * hash = new uint8_t[32];
   // printf("\n\ninside digest\n\n ");
	pad();
   // printf("\n\npad pass\n\n ");
	revert(hash);

	return hash;
}

uint32_t SHA256::rotr(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

uint32_t SHA256::choose(uint32_t e, uint32_t f, uint32_t g) {
	return (e & f) ^ (~e & g);
}

uint32_t SHA256::majority(uint32_t a, uint32_t b, uint32_t c) {
	return (a & (b | c)) | (b & c);
}

uint32_t SHA256::sig0(uint32_t x) {
	return SHA256::rotr(x, 7) ^ SHA256::rotr(x, 18) ^ (x >> 3);
}

uint32_t SHA256::sig1(uint32_t x) {
	return SHA256::rotr(x, 17) ^ SHA256::rotr(x, 19) ^ (x >> 10);
}

void SHA256::transform() {
	uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
	uint32_t state[8];

	for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) { // Split data in 32 bit blocks for the 16 first words
		m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | (m_data[j + 3]);
	}
  /*  for(int debug=0;debug<16;debug++){
       printf("%ud\n",m[debug]);
	}*/
	for (uint8_t k = 16 ; k < 64; k++) { // Remaining 48 blocks
		m[k] = SHA256::sig1(m[k - 2]) + m[k - 7] + SHA256::sig0(m[k - 15]) + m[k - 16];
	}

	for(uint8_t i = 0 ; i < 8 ; i++) {
		state[i] = m_state[i];
	}

	for (uint8_t i = 0; i < 64; i++) {
		maj   = SHA256::majority(state[0], state[1], state[2]);
		xorA  = SHA256::rotr(state[0], 2) ^ SHA256::rotr(state[0], 13) ^ SHA256::rotr(state[0], 22);

		ch = choose(state[4], state[5], state[6]);

		xorE  = SHA256::rotr(state[4], 6) ^ SHA256::rotr(state[4], 11) ^ SHA256::rotr(state[4], 25);

		sum  = m[i] + K[i] + state[7] + ch + xorE;
		newA = xorA + maj + sum;
		newE = state[3] + sum;

		state[7] = state[6];
		state[6] = state[5];
		state[5] = state[4];
		state[4] = newE;
		state[3] = state[2];
		state[2] = state[1];
		state[1] = state[0];
		state[0] = newA;
	}

	for(uint8_t i = 0 ; i < 8 ; i++) {
		m_state[i] += state[i];
	}
}

void SHA256::pad() {

	uint64_t i = m_blocklen;
	uint8_t end = m_blocklen < 56 ? 56 : 64;

	m_data[i++] = 0x80; // Append a bit 1
	while (i < end) {
		m_data[i++] = 0x00; // Pad with zeros
	}
	
	if(m_blocklen >= 56) {
		transform();
		//memset(m_data, 0, 56);
		for(int g=0;g<56;g++){
			m_data[g]=0;
		}
	}

	// Append to the padding the total message's length in bits and transform.
//	printf("   %lu   ",m_bitlen);
	m_bitlen += m_blocklen * 8;
	//printf("   %lu   ",m_bitlen);
	m_data[63] = m_bitlen;
	m_data[62] = m_bitlen >> 8;
	m_data[61] = m_bitlen >> 16;
	m_data[60] = m_bitlen >> 24;
	m_data[59] = m_bitlen >> 32;
	m_data[58] = m_bitlen >> 40;
	m_data[57] = m_bitlen >> 48;
	m_data[56] = m_bitlen >> 56;

    /*printf("\n");
    for(int hj=0;hj<64;hj++){
           printf("%02x\n",m_data[hj])   ;
	}*/


	transform();
}

void SHA256::revert(uint8_t * hash) {
	// SHA uses big endian byte ordering
	// Revert all bytes

   // printf("hello");

	for (uint8_t i = 0 ; i < 4 ; i++) {
		for(uint8_t j = 0 ; j < 8 ; j++) {
			hash[i + (j * 4)] = (m_state[j] >> (24 - i * 8)) & 0x000000ff;
            //printf("%d",(i+(j*4)));
		}
	}
}



// class declaration and definition ends 

struct Publickey
            { char Modulus[512];
            int Exponent; 
            };

struct   Publickey pol;//for storing public key(from X509) (a RSA)
char Reference[1000];
char Sha_reference[64];//1
char Sha_SignedInfo[64];//2
char Digest_ref_hex[64];//1
char Signed_val_hex[464];//2() (b RSA)

class
Xml_validator{

    private:
      
        
        bool Result;//final result will be stored here

        FILE *fp;//pointer to Permission artifact
       // FILE *fw_R;//new files for storing reference 
        char file_name_perm[30];

      //  unsigned char Reference_sec[1500];

        char Tag_X509[16]="X509Certificate";//tag used to get certificate

        char X509[1100];//certificate ASN.1 coded

        char Tag_Digest_value[12]="DigestValue";
        char Digest_Value[100];

        char Tag_Signed_Value[17]="SignatureValue";
        char Signed_Value[250];

        char Signed_Info_Tag[18]="SignedInfo";
        unsigned char Signed_Info[1000];
        
        unsigned char *Digest_Reference;
        
       

        unsigned char *Digest_signed;

     //   unsigned char **Digest_signed_RSA;

       

        char* strip(char *str) 
        {
        size_t len = strlen(str);
        memmove(str, str+1, len-2);
        str[len-2] = 0;
        return str;
        }

      

        

int isSubstring(char *s1, char *s2)///s1 is the sub string ; s2 is the larger string
{
    int M = strlen(s1);
 //  printf("11 %s jkl\n",s1);
    int N = strlen(s2);
  // printf("22 %s jkl\n",s2);
 
    for (int i = 0; i <= N - M; i++) {
        int j;
 
        for (j = 0; j < M; j++)
            if (s2[i + j] != s1[j])
                break;
 
        if (j == M)
            return i;
    }
    return -1;
}
        struct Digest
        {
        char **ptr;
        int len;
        };

public:
    bool getResult(){
        return Result;
    }


/* 
    the constructor makes two other files for processing
    (canonicalization has to be taken care of here only)
    and assigns the values to Digest Value,Signed value and X509 
    */
    Xml_validator(char *Permission_Artifact);


    /*function 1
    This will be used to calculate the digest of newly generated :
    Reference(inside file) and Signed Info(in string format)
    */

    void Calculating_Digest_Sha256(){
    
        int it =0;
        SHA256 sha_signedinfo;
        sha_signedinfo.update(Signed_Info,strlen((char*)Signed_Info));
        Digest_signed=sha_signedinfo.digest();
        printf("\n");
        int aux0;
        int count_digest=0;
       /* while(it<32){//program for converting digest reference to hex
		    printf("%02x",*(Digest_signed+it));
		    it++;
	    }*/
        it=0;
        while(it<32){
		    
            aux0=(*(Digest_signed+it)<<24)|(*(Digest_signed+it+1)<<16)|(*(Digest_signed+it+2)<<8)|*(Digest_signed+it+3);
            
            for(int h=28;h>=0;h=h-4){
               Sha_SignedInfo [count_digest] =HEX_DIGITS[(aux0>>h)&0xf];
               count_digest++;
            }
            
		    it=it+4;
	    }

     //   FILE *fpp;
        // fp=fopen("permission_artifact_1.xml","r");
     //   fpp=fopen("Reference1.txt","r");
      //  if (fpp==NULL){

      //  printf("Can not open file");
      //  exit(1);
      //  }
        char ch;
        int fpp=0;
        unsigned char st[3000];
        unsigned int i=0;
        while(1){
            ch=Reference[fpp];
            if(ch=='\0')
            break;
		    if(ch!='\n'){
            st[i]=ch;
		    //printf("%c",*(st+i));
		    i++;
            fpp++;
		    }
        
            // printf("%c",ch);
    }
	   // printf("\n");
	    printf("\n");
    
        SHA256 sha;

	    sha.update(st,i);

	    uint8_t * digest = sha.digest();
        it=0;//just an iterator
	//printing digest
	    printf("\n");
        int aux1;
        count_digest=0;
       /* for(int k=0;k<32;k++){
            printf("%02x ",*(digest+k));
        }*/
        while(it<32){
		    
            aux1=(*(digest+it)<<24)|(*(digest+it+1)<<16)|(*(digest+it+2)<<8)|*(digest+it+3);
            
            for(int h=28;h>=0;h=h-4){
               Sha_reference[count_digest] =HEX_DIGITS[(aux1>>h)&0xf];
               count_digest++;
            }
            
		    it=it+4;
	    }

	    printf("\n");

	   // delete[] digest;
    
        //delete []st;
       /// st=NULL;
      ///  printf("\nnumber of characters in file are :%d\n",i);
       // fclose(fpp);
    
}


/*function 2
Input:Signed_Value,Public key
Output:Digest(Base64/Hex)
*/
    void RSA_Decryption(){
    
    }

/*function 3
Input:Base64 encoded X509 certificate
Output:Public_Key
1)Exponent
2)Modulus
*/

    int inBase64(char *d){
        for(int i=0;i<64;i++){
            if(*d==BASE64_DIGITS[i]){
                return i;
            }
        }
    }

    void base64decoder(char *base64_ptr){
        int length_str=0;
        while(*base64_ptr!='\0'){
            length_str++;
            base64_ptr++;
        }
        base64_ptr=base64_ptr-length_str;
     // printf("\nlength %d\n",length_str);
        int size_of_hex;
        if((length_str*6)%8!=0){
            printf("invalid base64 to hex\n");
         }
        size_of_hex=(length_str*6)/8;
        printf("\n\n\n%d\n",(int)2*size_of_hex);
        char *hex=(char*) malloc(sizeof(char)*(2*size_of_hex+100));
    
    
        int ik=0;



        int aux1,aux2,aux3,num_bits;
    
        for(int i=0;i<length_str;i=i+4){
            aux1=0;num_bits=0;

            for(int j=0;j<4;j++){

                if(base64_ptr[i+j]!='='){
                    aux1=aux1<<6;
                    num_bits=num_bits+6;
        
                    aux2=inBase64(&base64_ptr[i+j]);
      
        
                    aux1=aux1|aux2;
      

                }else{
                    aux1=aux1>>2;
                    num_bits=num_bits-2;
                    }
        
            }
       
            int count_bit=num_bits;
            while(num_bits!=0){
                num_bits=num_bits-4;
                aux3=(aux1>>num_bits) & 15;
           

           // printf("aux3:: %d ",aux3);
                hex[ik]=HEX_DIGITS[aux3];
           
            
          // printf("%c |",hex[ik]);
                ik++;
            }
       
         // printf("\n");
       

        }
   
        //printf("length %d\n",ik);
       // printf("\n");
        int i=276;
        int modu_count=0;
        while(i<274+514 ){
          //  printf("%c",hex[i]);
            pol.Modulus[modu_count]=hex[i];
            modu_count++;
            i++;
        }
        free(hex);
        printf("\n");

    }

    void X509_to_PublicKey(){
        pol.Exponent=65537;
        base64decoder(X509);
    }

//function 4
void Base64_to_Hex(char *ptr,char *result){
    
    int length_str=0;
    while(*ptr!='\0'){
        length_str++;
        ptr++;
    }
    ptr=ptr-length_str;
   // printf("\nlength %d\n",length_str);
    int size_of_hex;
    if((length_str*6)%8!=0){
        printf("invalid base64 to hex\n");
    }
    size_of_hex=(length_str*6)/8;
    int hex_ptr_ctr=0;
    char *hex=(char*) malloc(sizeof(char)*(2*size_of_hex+100));
    
    
    int ik=0;



    int aux1,aux2,aux3,num_bits;
    
    for(int i=0;i<length_str;i=i+4){
        aux1=0;num_bits=0;

        for(int j=0;j<4;j++){

        if(ptr[i+j]!='='){
        aux1=aux1<<6;
        num_bits=num_bits+6;
        
        aux2=inBase64(&ptr[i+j]);
      
        
        aux1=aux1|aux2;
      

        }else{
            aux1=aux1>>2;
            num_bits=num_bits-2;
        }
        
        }
       
        int count_bit=num_bits;
        while(num_bits!=0){
            num_bits=num_bits-4;
            aux3=(aux1>>num_bits) & 15;
           

           // printf("aux3:: %d ",aux3);
            hex[ik]=HEX_DIGITS[aux3];
            *(result+ik)=hex[ik];
          // printf("%c |",hex[ik]);
            ik++;
        }
       
       // printf("\n");
       

    }

   free(hex);  
}



/*function 6
digest_value(Base64/Hex)==Digest_Reference(Base64/Hex)
Digest_signed_RSA(Base64/Hex)==Digest_signed(Base64/Hex);
Output goes to result.
*/
void Comparator_Validate(){
    struct bn n2048, pub2, priv2, v2Dec2,r2m,result,aux;
	
    int e1=pol.Exponent;
	bignum_from_int(&pub2,e1);//public key
	//char str7[] = "ab9d5c8d1fe67207749d63b7dcedd233ce32bb70d175a1bc38c612ab33e2c58e51f83f2788e4d52d9bceb5a1513929de3f526650071a067e6c161b05c60a495fc3ba79ed26f4fa8b2fe2ca8dec44b39759f39206f06a85f9424005a29f05e4cf3a0239340c28c993c1a61cf1b2b6b57c7d8e576ae86827f812b327625baec9ecbf55f1651d35600b9f955f6c2f3bea3aa5852ecdd36a0af818c19acc1030979bed3c89993faa92e0aa0502413b3ca86bbf63477f12ac069aff7137cb72c57f886da79033bbb3b4df0f6cc7fcc18e343aa76036681a566311e267c03b65c98abc91e58f090020c67f776199c0eb76d7e6363687475d3da36ff050f85275607fdd";
	bignum_from_string(&n2048,pol.Modulus, 512);//modulus
	bignum_from_string(&v2Dec2,Signed_val_hex,64);//value to decrypt/encrypt
	char r2ms2[]= "11a002f5e3f4cc842b0a994927edbc19c30af2a84156fa8d69c8f233190545560b004e23870eab7ef04367934d2f889208dbe44ae686661ba9eae2be47483ef3e6fc2d66240db0f9309b83f1a8ac4468d24d8b47ed7c5a7c93d803e090078202f7cc22887ac9dc8afb5fd97a4dc82f4bf344a31922686de17fcd7042de1662eabc332c97b7e61f70afb2b65de46ee9a692192f7e50ea88242b9eeb841e4b4a16a102a2e3194a8e8ed637307e603bde8ac7183f8230c2eb2707757ad7a599a51bc68956760fea5cd6b3baebcf12f71e7d4020b9df21f18dc119ddb17fc0c39f8ebec5ca8d9c9d1173dad8846468cab704b4a3a5e29894d891855148e161ca3695";
	bignum_from_string(&r2m,r2ms2,512);// montgomery aux
   // bignum_print(&r2m);
	

	int nBits = bignum_numbits(&n2048);
	int eBits=bignum_numbits(&pub2);
	bignum_init(&result);
	modExp(&v2Dec2, &pub2,eBits, &n2048, nBits, &r2m, &result);
  //  printf("\n");
  //  printf("\n printing result \n");
	//bignum_print(&result);
    char res2[200];
    bignum_to_string(&result, res2, 400);

    // comparison 1
    int ci=0;
    int check1,check2;
    while(1){
        if(res2[ci]!=Sha_SignedInfo[ci]){
                break;
        }else{
            if(ci>63){
                break;
            }
        }
        ci++;

    }
    if(ci==64){
        check1=1;
    }else{
        check1=0;
    }

    ci=0;
    while(1){
        if(Digest_ref_hex[ci]!=Sha_reference[ci]){
                break;
        }else{
            if(ci>63){
                break;
            }
        }
        ci++;

    }
    if(ci==64){
        check2=1;
    }else{
        check2=0;
    }
    //validate condition
    if(check1==1 && check2==1){
        Result=1;
    }
    else{
        Result=0;
    }

}

/*function 7
*/
char* Canonical(char*);


//function get tag value
Digest getTagvalue(char *Tag, char *certificate){
    fp=fopen(file_name_perm,"r");
    Digest DD;
    
    char buf[3000];
    
    char tagi[30];
    char tage[30];
    
    memset(tagi, 0, sizeof(tagi));
    strcpy(tagi, "<");
    strcat(tagi,Tag );
    strcat(tagi, ">");
    
    memset(tage, 0, sizeof(tage));
    strcpy(tage, "</");
    strcat(tage,Tag );
    strcat(tage, ">");

    char *ptr1,*ptr2;
  
    int c_flag_i=0,c_flag_e=0,line=0;

    int index[2][2]={{0,0},{0,0}};
   
    int  aux=0;
  
    int c=0;
  
   while(fscanf(fp, "%s", buf) != EOF )
    {  
    line=line+1;
    if(isSubstring(tagi,buf)!=-1 || isSubstring(tage,buf)!=-1 ){
      //  printf(" %d ",line);
        if (isSubstring(tagi,buf)!=-1){       //for "<X509Certificate>"
          // printf("start");
           index[0][0]=line;
           index[0][1]=isSubstring(tagi,buf);
           c_flag_i=1;
           aux=1;
           
        }
        if(isSubstring(tage,buf)!=-1){                          //for "</X509Certificate>"
          // printf("  end");
           index[1][0]=line;
           index[1][1]=isSubstring(tage,buf);
          // printf("\n%d   %d\n",index[1][0],index[1][1]);
           c_flag_e=1;
           
         
        }
        }  
        
        if(c_flag_i==1 && c_flag_e==0 ){
        if (aux==1){

        for(int u=index[0][1]+strlen(tagi);u<strlen(buf);u++){
            certificate[c]=buf[u];
         
            c++;
        }
         
        aux=0;
        }
        else{ptr1=certificate+c;
            ptr2=&(buf[0]);
            memcpy(ptr1,ptr2,strlen(buf));
            c=c+strlen(buf);
        }
        }
        else if(c_flag_i==1 && c_flag_e==1 )
        {  
            if(index[0][0]==index[1][0])//start line and end line is same
        {
            for(int u=index[0][1]+strlen(tagi);u<index[1][1];u++)
            {
            certificate[c]=buf[u];
            c++;
            }
           
        }else
        {  //end line is different than start line
           for(int u=0;u<index[1][1];u++)
            {
            certificate[c]=buf[u];
            c++;
            }
            
        }
        break;
        }else{continue;}
        
    }
    fclose(fp);
    DD.len=c;
    DD.ptr=&certificate;
    return DD;
}



/////////////////////


void bignum_inc(struct bn* n)
{
  

  DTYPE res;
  DTYPE_TMP tmp; /* copy of n */

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    tmp = n->array[i];
    res = tmp + 1;
    n->array[i] = res;

    if (res > tmp)
    {
      break;
    }
  }
}

void bignum_dec(struct bn* n)
{
  

  DTYPE tmp; /* copy of n */
  DTYPE res;

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    tmp = n->array[i];
    res = tmp - 1;
    n->array[i] = res;

    if (!(res > tmp))
    {
      break;
    }
  }
}
void bignum_init(struct bn* n)
{
	register int z = z-z;
	int i = z;
	n->array[0] = z;
	for (i = BN_ARRAY_SIZE - 1; i > 0; i -=4)
	{
		n->array[i] = z;
		n->array[i-1] = z;
		n->array[i-2] = z;
		n->array[i-3] = z;
	}
}
void bignum_pow(struct bn* a, struct bn* b, struct bn* c)
{
 

  struct bn tmp;

  bignum_init(c);

  if (bignum_cmp(b, c) == EQUAL)
  {
    /* Return 1 when exponent is 0 -- n^0 = 1 */
    bignum_inc(c);
  }
  else
  {
    struct bn bcopy;
    bignum_assign(&bcopy, b);

    /* Copy a -> tmp */
    bignum_assign(&tmp, a);

    bignum_dec(&bcopy);
 
    /* Begin summing products: */
    while (!bignum_is_zero(&bcopy))
    {

      /* c = tmp * tmp */
      bignum_mul(&tmp, a, c);
      /* Decrement b by one */
      bignum_dec(&bcopy);

      bignum_assign(&tmp, c);
    }

    /* c = tmp */
    bignum_assign(c, &tmp);
  }
}

void bignum_from_int(struct bn* n, DTYPE_TMP i)
{
	bignum_init(n);

	/* Endianness issue if machine is not little-endian? */
#ifdef WORD_SIZE
#if (WORD_SIZE == 1)
	n->array[0] = (i & 0x000000ff);
	n->array[1] = (i & 0x0000ff00) >> 8;
	n->array[2] = (i & 0x00ff0000) >> 16;
	n->array[3] = (i & 0xff000000) >> 24;
#elif (WORD_SIZE == 2)
	n->array[0] = (i & 0x0000ffff);
	n->array[1] = (i & 0xffff0000) >> 16;
#elif (WORD_SIZE == 4)
	n->array[0] = i;
	DTYPE_TMP num_32 = 32;
	DTYPE_TMP tmp = i >> num_32; /* bit-shift with U64 operands to force 64-bit results */
	n->array[1] = tmp;
#endif
#endif
}

int bignum_to_int(struct bn* n)
{
	return n->array[0];
}

void bignum_from_string(struct bn* n, char* str, int nbytes)
{
	bignum_init(n);

	DTYPE tmp;                        /* DTYPE is defined in bn.h - uint{8,16,32,64}_t */
	int i = nbytes - (2 * WORD_SIZE); /* index into string */
	int j = 0;                        /* index into array */

	/* reading last hex-byte "MSB" from string first -> big endian */
	/* MSB ~= most significant byte / block ? :) */
	while (i >= 0)
	{
		tmp = 0;
		sscanf(&str[i], SSCANF_FORMAT_STR, &tmp);
		n->array[j] = tmp;
		i -= (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) back in the string. */
		j += 1;               /* step one element forward in the array. */
	}
}

static void _lshift_word(struct bn* a, int nwords)
{
 

  int i;
  /* Shift whole words */
  for (i = (BN_ARRAY_SIZE - 1); i >= nwords; --i)
  {
    a->array[i] = a->array[i - nwords];
  }
  /* Zero pad shifted words. */
  for (; i >= 0; --i)
  {
    a->array[i] = 0;
  }  
}

void bignum_mod(struct bn* a, struct bn* b, struct bn* c)
{
  /*
    Take divmod and throw away div part
  */
 

  struct bn tmp;

  bignum_divmod(a,b,&tmp,c);
}

void bignum_mul(struct bn* a, struct bn* b, struct bn* c)
{
  
  struct bn row;
  struct bn tmp;
  int i, j;

  bignum_init(c);

  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    bignum_init(&row);

    for (j = 0; j < BN_ARRAY_SIZE; ++j)
    {
      if (i + j < BN_ARRAY_SIZE)
      {
        bignum_init(&tmp);
        DTYPE_TMP intermediate = ((DTYPE_TMP)a->array[i] * (DTYPE_TMP)b->array[j]);
        bignum_from_int(&tmp, intermediate);
        _lshift_word(&tmp, i + j);
        bignum_add(&tmp, &row, &row);
      }
    }
    bignum_add(c, &row, c);
  }
}

void bignum_to_string(struct bn* n, char* str, int nbytes)
{
	int j = BN_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
	int i = 0;                 /* index into string representation. */

	/* reading last array-element "MSB" first -> big endian */
	while ((j >= 0) && (nbytes > (i + 1)))
	{
		sprintf(&str[i], SPRINTF_FORMAT_STR, n->array[j]);
		i += (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) forward in the string. */
		j -= 1;               /* step one element back in the array. */
	}

	/* Count leading zeros: */
	j = 0;
	while (str[j] == '0')
	{
		j += 1;
	}

	/* Move string j places ahead, effectively skipping leading zeros */
	for (i = 0; i < (nbytes - j); ++i)
	{
		str[i] = str[i + j];
	}

	/* Zero-terminate string */
	str[i] = 0;
}

void bignum_add(struct bn* a, struct bn* b, struct bn* c)
{
	DTYPE_TMP tmp;
	int carry = carry - carry;
	int i = 1;

	tmp = (DTYPE_TMP)a->array[0] + b->array[0] + carry;
	carry = (tmp > MAX_VAL);
	c->array[0] = (tmp & MAX_VAL);

	for (; i < BN_ARRAY_SIZE; i+=4)
	{

		tmp = (DTYPE_TMP)a->array[i] + b->array[i] + carry;
		carry = (tmp > MAX_VAL);
		c->array[i] = (tmp & MAX_VAL);

		tmp = (DTYPE_TMP)a->array[i+1] + b->array[i+1] + carry;
		carry = (tmp > MAX_VAL);
		c->array[i+1] = (tmp & MAX_VAL);

		tmp = (DTYPE_TMP)a->array[i+2] + b->array[i+2] + carry;
		carry = (tmp > MAX_VAL);
		c->array[i+2] = (tmp & MAX_VAL);

		tmp = (DTYPE_TMP)a->array[i+3] + b->array[i+3] + carry;
		carry = (tmp > MAX_VAL);
		c->array[i+3] = (tmp & MAX_VAL);
	}
}

void bignum_sub(struct bn* a, struct bn* b, struct bn* c)
{
	DTYPE_TMP res;
	DTYPE_TMP tmp1;
	DTYPE_TMP tmp2;
	register int zero  = zero - zero;
	int borrow = zero;
	int i = zero;
	for (; i < BN_ARRAY_SIZE; ++i)
	{
		tmp1 = (DTYPE_TMP)a->array[i] + (MAX_VAL + 1); /* + number_base */
		tmp2 = (DTYPE_TMP)b->array[i] + borrow;;
		res = (tmp1 - tmp2);
		c->array[i] = (DTYPE)(res & MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if number_base is 2^N */
		borrow = (res <= MAX_VAL);
	}
}

void bignum_rshift(struct bn* a, struct bn* b, int nbits)
{
	/* Handle shift in multiples of word-size */
	int nwords = nbits >> 5;
	if (nwords != 0)
	{
		int z = nwords << 5;
		_rshift_word(a, nwords);
		nbits -= (z);
	}

	if (nbits != 0)
	{
		int z = 32 - nbits;
		int i;
		for (i = 0; i < (BN_ARRAY_SIZE - 1); i++)
		{
			a->array[i] = (a->array[i] >> nbits) | (a->array[i + 1] << (z));
		}
		a->array[i] >>= nbits;
	}
}
int bignum_cmp(struct bn* a, struct bn* b)
{
	int i = BN_ARRAY_SIZE;
	do
	{
		i -= 1; /* Decrement first, to start with last array element */
		if (a->array[i] > b->array[i])
		{
			return LARGER;
		}
		else if (a->array[i] < b->array[i])
		{
			return SMALLER;
		}
	}
	while (i != 0);

	return EQUAL;
}

void bignum_assign(struct bn* dst, struct bn* src)
{
	register int i = BN_ARRAY_SIZE-1;
	for (; i > 0; i-=4)		//loop opt
	{
		dst->array[i] = src->array[i];
		dst->array[i-1] = src->array[i-1];
		dst->array[i-2] = src->array[i-2];
		dst->array[i-3] = src->array[i-3];

	}
	dst->array[0] = src->array[0];

}

int bignum_getbit(struct bn* a, int n){
	int arrayInd = (n >> 5);
	int shift = (n - (arrayInd << 5));
	return (a->array[arrayInd] >> shift) & 1;
}

int bignum_numbits(struct bn* bn){

	register int f = (BN_ARRAY_SIZE << 5) -1;

	for (;f > 0; --f){
		int b = bignum_getbit(bn, f);
		if (b == 1){
			return f+1;
		}
	}
	return 0;
}

void bignum_print(struct bn* num){

	int size = 8192;
	char str[size];
	bignum_to_string(num, str, size);
	printf(" %s\n",str);
}

static void _lshift_one_bit(struct bn* a)
{
  

  int i;
  for (i = (BN_ARRAY_SIZE - 1); i > 0; --i)
  {
    a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * WORD_SIZE) - 1));
  }
  a->array[0] <<= 1;
}



void bignum_or(struct bn* a, struct bn* b, struct bn* c)
{
  

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    c->array[i] = (a->array[i] | b->array[i]);
  }
}



static void _rshift_one_bit(struct bn* a)
{
 

  int i;
  for (i = 0; i < (BN_ARRAY_SIZE - 1); ++i)
  {
    a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * WORD_SIZE) - 1));
  }
  a->array[BN_ARRAY_SIZE - 1] >>= 1;
}
void bignum_div(struct bn* a, struct bn* b, struct bn* c)
{
  

  struct bn current;
  struct bn denom;
  struct bn tmp;

  bignum_from_int(&current, 1);               // int current = 1;
  bignum_assign(&denom, b);                   // denom = b
  bignum_assign(&tmp, a);                     // tmp   = a

  const DTYPE_TMP half_max = 1 + (DTYPE_TMP)(MAX_VAL / 2);
  bool overflow = false;
 // printf("ffffffffffff\n");
  while (bignum_cmp(&denom, a) != LARGER)     // while (denom <= a) {
  {
    if (denom.array[BN_ARRAY_SIZE - 1] >= half_max)
    {
      overflow = true;
	//  printf("heeeeeeeeeee");
      break;
    }
	//printf("ddddddddd");
    _lshift_one_bit(&current);                //   current <<= 1;
    _lshift_one_bit(&denom);                  //   denom <<= 1;
  }
  if (!overflow)
  {
    _rshift_one_bit(&denom);                  // denom >>= 1;
    _rshift_one_bit(&current);                // current >>= 1;
  }
  bignum_init(c);                             // int answer = 0;

  while (!bignum_is_zero(&current))           // while (current != 0)
  {
    if (bignum_cmp(&tmp, &denom) != SMALLER)  //   if (dividend >= denom)
    {
      bignum_sub(&tmp, &denom, &tmp);         //     dividend -= denom;
      bignum_or(c, &current, c);              //     answer |= current;
    }
    _rshift_one_bit(&current);                //   current >>= 1;
    _rshift_one_bit(&denom);                  //   denom >>= 1;
  }                                           // return answer;
}

void bignum_divmod(struct bn* a, struct bn* b, struct bn* c, struct bn* d)
{
  /*
    Puts a%b in d
    and a/b in c
    mod(a,b) = a - ((a / b) * b)
    example:
      mod(8, 3) = 8 - ((8 / 3) * 3) = 2
  */
  

  struct bn tmp;

  /* c = (a / b) */
  bignum_div(a, b, c);

  /* tmp = (c * b) */
  bignum_mul(c, b, &tmp);

  /* c = a - tmp */
  bignum_sub(a, &tmp, d);
}

static void _rshift_word(struct bn* a, int nwords)
{
	register int i = i-i;
	for (; i < nwords; i+=4)
	{
		a->array[i]   = a->array[i + 1];
		a->array[i+1] = a->array[i + 2];
		a->array[i+2] = a->array[i + 3];
		a->array[i+3] = a->array[i + 4];
	}
	register int z = z-z;
	for (; i < BN_ARRAY_SIZE; i+=4)
	{
		a->array[i]   = z;
		a->array[i+1] = z;
		a->array[i+2] = z;
		a->array[i+3] = z;
	}
}


/*
 * Performs bitwise Montgomery modular multiplication ( X*Y*R^(-1) mod M)
 *
 * Parameters:
 * 		x,y,m - bignums
 * 		mBits - # of bits in m
 * 		out	  - bignum result
 */

void montMult(struct bn*  x, struct bn*  y, struct bn*  m, int mBits, struct bn*  out){

	struct bn t;
	bignum_init(&t);

	int i;
	for(i = mBits; i > 0 ; i--){					//efficient loop exit

		int t0Bit = bignum_getbit(&t,0);
		int xiBit = bignum_getbit(x, mBits - i);	//loop exit requires subtraction here
		int y0Bit = bignum_getbit(y,0);
		int op = t0Bit + (xiBit * y0Bit);

		if(xiBit == 1){
			bignum_add(&t, y, &t);
		}

		if(op == 1){
			bignum_add(&t, m, &t);
		}

		bignum_rshift(&t,&t, 1);
	}

	if(bignum_cmp(&t, m) >= 0){
		bignum_sub(&t,m,&t);
	}

	bignum_assign(out,&t);
}

int bignum_is_zero(struct bn* n)
{
 

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    if (n->array[i])
    {
      return 0;
    }
  }

  return 1;
}


void modExp(struct bn*  x, struct bn*   e, int eBits, struct bn*  m, int mBits, struct bn*  r2m,  struct bn*   out){

	struct bn z,one;
	struct bn parr[3];
	struct bn zarr[3];

	//reduce z?
	bignum_from_int(&z, 1);
	montMult(&z,r2m,m, mBits, &zarr[1]);

	//reduce x, assign to p
	montMult(x,r2m,m, mBits,&parr[1]);

	struct bn tm;

	int i = 0;
	for(; i < eBits; i++){

		bignum_assign(&tm, &parr[1]);
		montMult(&tm,&parr[1],m, mBits, &parr[2]);

		if(bignum_getbit(e, i) == 1){
			montMult(&zarr[1],&parr[1],m,mBits,&zarr[2]);
		}else{
			bignum_assign(&zarr[2],&zarr[1]);
		}

		//printf("num bits p: %d, num bits z: %d\n", bignum_numbits(&parr[1]), bignum_numbits(&zarr[1]));
		bignum_assign(&parr[1], &parr[2]);
		bignum_assign(&zarr[1], &zarr[2]);
	}

	bignum_from_int(&one, 1);
	montMult(&zarr[1], &one, m, mBits, out);
}



////////////////////////
}
;


Xml_validator::Xml_validator(char* file){
    
    char *certificate=(char*)malloc(sizeof(char)*5000);//dynamically created array 
    
  
    strcpy(file_name_perm,file);

    Digest certificatev,Digestv,Signed,SignedI;
    //storing X509 certificate value
    certificatev=getTagvalue(Tag_X509,certificate);

    for(int i=0;i<certificatev.len;i++)
    {
        X509[i]=*(i+*(certificatev.ptr));
    }


    // storing Digest value
    Digestv=getTagvalue(Tag_Digest_value,certificate);
  //  printf("\nhello  %d\n",Digestv.len);
   
    for(int i=0;i<Digestv.len;i++)
    {
        Digest_Value[i]=*(i+*(Digestv.ptr));
    }

    // storing Signed value
    Signed=getTagvalue(Tag_Signed_Value,certificate);

    
    for(int i=0;i<Signed.len;i++){
        Signed_Value[i]=*(i+*(Signed.ptr));
    }
    // storing Signed Info
    SignedI=getTagvalue(Signed_Info_Tag,certificate);

    
    for(int i=0;i<SignedI.len;i++)
    {
        Signed_Info[i]=*(i+*(SignedI.ptr));
    }
   
   
    // generating two files (reference and signed info)
   
   // FILE *fw_R;
   // fw_R=fopen("Reference1.txt","w+");
  //  printf("\ncount id %d\n",c);
 //   printf("printing Signature section\n");
  //  for(int i=0;i<c;i++){
   //     printf("%c",certificate[i]);
   //     }



  //  printf("\noooooooooooo");
  //  printf("\n");
  //  printf("printing X509certificate \n");
  //  for(int i=0;i<certificatev.len;i++){
  //      printf("%c",X509[i]);
   // }
    
   // printf("\noooooooooooo");
  //  printf("\n");
   // printf("printing Signed Info \n");
  //  for(int i=0;i<SignedI.len;i++){
  ///      printf("%c",Signed_Info[i]);
   // }


  //  printf("\n");
   // printf("\noooooooooooo");
   // printf("\nprinting Digest value\n");
  //  for(int i=0;i<Digestv.len;i++){
  //      printf("%c",Digest_Value[i]);
   // }
   // printf("\n");
   // printf("\noooooooooooo");
   // printf("\nprinting Signed value\n");
  //  for(int i=0;i<Signed.len;i++){
   //     printf("%c",Signed_Value[i]);
   // }
  //  printf("\n\n");
  //fclose(fw_R);
  //  free(Reference);
    free(certificate);
///////////////


    X509_to_PublicKey();

    Calculating_Digest_Sha256();
  


    // getting Digest reference in hex(earlier it was in base 64)
    
   

    Base64_to_Hex(Digest_Value,Digest_ref_hex);
  


    //getting signed value in hex

    
    
    Base64_to_Hex(Signed_Value,Signed_val_hex);
  
    printf("\n");



    //// validation
    Comparator_Validate();

}




int main(){
    
    char filename[30]="permission_artifact_1.xml";

    Xml_validator validate(filename);
    printf("\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("The status of validation is  %d",validate.getResult());
   
    printf("\n\n");   
    return 0;
}