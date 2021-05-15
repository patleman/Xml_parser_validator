#include<stdio.h>
#include<stdlib.h>

#include<string.h>
using namespace std;

int find_int_hex(char ptr){
    char char_set16[]="0123456789ABCDEF";
    int i=0;
    while(1){
        if(char_set16[i]==ptr){
            return i;
        }
        i++;
    }

}

char* base64Encoder(char input_str[], int len_str)
{

    //character set of base 64 encoding scheme
    char char_set[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char char_set16[]="0123456789ABCDEF";

    char *res_str=(char *) malloc(1000 * sizeof(char));//chr *res_str =new char(1000*1)

    if(len_str%2!=0){ 
        printf("the hex string is not valid for having conversion to base64 digits");
        exit(1);
    }

    int i=len_str;

    /* basic agenda
    an initial check that number of char in string are even or not (gouping of bytes(8 bits= 2 hex char) is done)
    first check if 6 continous hex digits could be taken or not 
    if yes:
    1)  Take 6 hex digits :24 bits
    2)  24/6=4 then write 4 base64 characters
    if no:
    1)check how many hex char are available(<6)
    2)possible cases 2,4
    if 2 hex char available:
        -add 4 bits(valued 0) to make the bit length divisible by 6
    if 4 hex char available 
        - add 2 bits(valued 0) to make the bit length divisible by 6    
    */
    int j=0;
    int res_count=0;
    while(1){
        if(i>=6){//if yes code starts here

            int aux=0;
           // printf("%d\n",res_count);
            for(int index=j ; index<j+6;index++){
                aux=(aux<<4);
              //  printf("%d ",find_int_hex(input_str[index]));
                aux=aux|find_int_hex(input_str[index]);
              //  printf(" %08x ",aux);
            }
            j=j+6;
            printf("\n");
            int aux1=0;
            for(int o=3;o>=0;o--){
                aux1=aux & 0x3f;
                res_str[res_count+o]=char_set[aux1];
                aux=aux>>6;
                //res_count--;
            }
            res_count=res_count+4;
            i=i-6;
        }else{

                if(i==0){
                    printf("Done...");
                    printf("\n");
                    break;
                }
                if(i==2){
                    int aux=0;
                    for(int index=j ; index<j+2;index++){
                            aux=(aux<<4);
                        //  printf("%d ",find_int_hex(input_str[index]));
                            aux=aux|find_int_hex(input_str[index]);
                            //  printf(" %08x ",aux);
                        }
                        aux=aux<<4;
                    int aux1=0;
                    for(int o=1;o>=0;o--){
                        aux1=aux & 0x3f;
                        res_str[res_count+o]=char_set[aux1];
                        aux=aux>>6;
                    //res_count--;
                    }
                    res_count=res_count+2;
                    res_str[res_count]='=';
                    res_count++;
                    res_str[res_count]='=';
                    res_count++;
                    res_str[res_count]='\0';
                    break;

                }else{

                    int aux=0;
                    for(int index=j ; index<j+4;index++){
                            aux=(aux<<4);
                        //  printf("%d ",find_int_hex(input_str[index]));
                            aux=aux|find_int_hex(input_str[index]);
                            //  printf(" %08x ",aux);
                        }
                        aux=aux<<2;
                    int aux1=0;
                    for(int o=2;o>=0;o--){
                        aux1=aux & 0x3f;
                        res_str[res_count+o]=char_set[aux1];
                        aux=aux>>6;
                    //res_count--;
                    }
                    res_count=res_count+3;
                    res_str[res_count]='=';
                    res_count++;
                    res_str[res_count]='\0';
                    break;


                }

        }


    }
    return res_str;

}



int main(){
    char *result;
    char input[34]="a12348";
    result=base64Encoder(input,(int)strlen(input));
    printf("\n The base 64 encoding of hex string is: %s \n",result);
    return 0;
}