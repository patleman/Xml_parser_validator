#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<inttypes.h>
//main purpose of this code is to extract Reference section and Signed info,
//while keeping in mind the rules of canonicalization.
using namespace std;
int aux_space_count;
struct stack{
    char list_att[40][40];
    int counter;
};

void updateStack_remove(char *ptr, stack *ss){
    int i=0;
    ss->counter=ss->counter-1;
    while(1){
    char t=ss->list_att[ss->counter][i];
    if (t=='\0'){
        break;
    }else{
        t=' ';
    }
    i=i+1;
    }

}

void updateStack_add(char *ptr,int set, stack *ss)
{
    int i=0;
 
    while(1){
      
        if(*(ptr+set+i+1)==' ' || *(ptr+set+i+1)=='>'){
         
            break;
        }
    
        ss->list_att[ss->counter][i]=ptr[set+i+1];
        i++;
    }
    ss->list_att[ss->counter][i]='\0';
   // printf("ha %s ha",ss->list_att[ss->counter]);
    ss->counter=ss->counter+1;


}

void replaceTag(char *ptr, stack *ss,char *result,int *ptr_count){
    char aux[40];
    int i=0;
    ss->counter=ss->counter-1;
    while(1){
        char aux_v=ss->list_att[ss->counter][i];
        if (aux_v=='\0' || aux_v==' '){
            if(aux_v=='\0'){
               // printf("endarray");
            }
            if(aux_v==' '){
               // printf("space");
            }
            break;
        }
        aux[i]=aux_v;
        i++; 
    }
   
  //  printf("%c",'>');
    result[*(ptr_count)]='>';
    *(ptr_count)=*(ptr_count)+1;
  //  printf("%c",'<');
    result[*(ptr_count)]='<';
    *(ptr_count)=*(ptr_count)+1;
   
   // printf("%c",'/');
    result[*(ptr_count)]='/';
    *(ptr_count)=*(ptr_count)+1;
  
    
    for(int f=0;f<i;f++){
       
       // printf("%c",aux[f]);
        result[*(ptr_count)]=aux[f];
        *(ptr_count)=*(ptr_count)+1;
    
    }
}

int isSignature(char *ptr){
    /* if signature start ::0
       if signature end ::1
       if none  ::2
    */
    char check0[18]="<Signature xmlns=";

    char check1[14]="</Signature>";

    char check2[14]="</SignedInfo>";

    char check3[13]="<SignedInfo>";
    
    int check0_status=1;

    for(int i=0;i<strlen(check0);i++)
    {
        if(*(ptr+i)!=check0[i])
        {
            check0_status=0;
            break;
        }
    }

    int check1_status=1;

    for(int i=0;i<strlen(check1);i++)
    {
        if(*(ptr+i)!=check1[i])
        {
            check1_status=0;
            break;
        }
    }

    int check2_status=1;
    for(int i=0;i<strlen(check2);i++){
        if(*(ptr+i)!=check2[i]){
            check2_status=0;
            break;
        }
    }


    int check3_status=1;
    for(int i=0;i<strlen(check3);i++){
        if(*(ptr+i)!=check3[i]){
            check3_status=0;
            break;
        }
    }

    if(check0_status==1){
        return 0;
    }
    if(check1_status==1){
        return 1;
    }
    if(check2_status==1){
        return 2;
    }
    if(check3_status==1){
        return 3;
    }
    return 4;

}

void Reference_canon(char *file_name, char *res){

    char space=' ';
    char new_line='\n';
   /* printf("space in hex:: %02x",space);
    printf("\n");
    printf("new_line in hex:: %02x",new_line);
    printf("\n");*/

    FILE *fp;

    char open_bracket='<';//  0
    char close_bracket='>';//  1
    char slash_bracket[3]="/>";//  2

    fp=fopen(file_name,"r");

    char ch;
    int count_result=0;
    int *ptr_count_result;
    ptr_count_result=&count_result;
    int i=0;

   

    char *content=(char*) malloc(sizeof(char)*10000);

    while(1)
    {
        
        ch=fgetc(fp);
        if(ch==EOF){
            break;
        }

        content[i]=ch;
        i++;
       
    }
    stack *dd;
    stack dds;
    dds.counter=0;
    dd=&dds;
   // printf("%d\n",i);

    int flag0=0,flag1=0;
    int aux_check_flag;
    int space_count=0;
    for(int u=0;u<i;u++)
    {

        if(content[u]=='<')
        { 
            aux_check_flag=isSignature(content+u);
            if(aux_check_flag==0)
                {   aux_space_count=space_count;
                    flag0=1;
                   // printf("  \n");
                  //  res[count_result]=' ';
                   // res[count_result+1]=' ';
                    res[count_result]=0x0a;//'\n';
                    count_result=count_result+1;
                }
            if(aux_check_flag==1){
                flag1=1;
                aux_space_count=space_count;
                u=u+12;

            }
            if(aux_check_flag==2){
                
            }
        }

        if(flag0==0 && flag1==0 || flag0==1 && flag1==1 )
        {
        
            if(content[u]=='<')
            {
                if(content[u+1]!='/')
                {  
                    updateStack_add(content,u,dd);
                    space_count=space_count+2;
                }
              
            }

            if(content[u]=='/' && content[u+1]=='>')
                {

                    replaceTag(content+u,dd,res,ptr_count_result);
                    space_count=space_count-2;
                
                }else{

               // printf("%c",content[u]);
                res[count_result]=content[u];
                count_result=count_result+1;
                }

            if(content[u]=='>' && content[u+1]=='<')
            {   
               // printf("\n");//new line 

                res[count_result]=0x0a;//'\n';

                count_result=count_result+1;

            
                if(content[u+2]=='/')
                {
                    updateStack_remove(content+u,dd);
                    /*printf("\nprinting stack::\n");
                    for(int i=0;i<dd->counter;i++){
                        printf("%s ",dd->list_att[i]);
                    }
                    printf("\n\n");*/
                     space_count=space_count-2;
                }
                
                for(int a=0;a<space_count;a++)
                {
                   // printf("%c",space);
                    res[count_result]=space;
                    count_result=count_result+1;
                }      
            


            }

        }

    }
    res[count_result]='\0';
  //  printf("\n\n");
    free(content);
}
///////////////


void SignedInfo_canon(char *file_name, char *res)
{
    char space=' ';
    char new_line='\n';
  //  printf("\n");
  //  printf("space in hex:: %02x",space);
  //  printf("\n");
  //  printf("new_line in hex:: %02x",new_line);
  //  printf("\n");
    FILE *fp;

    fp=fopen(file_name,"r");

    char *content=(char*) malloc(sizeof(char)*10000);
    
    char ch;
    char aux_copy[300];
    int count=0;
    int flag_ini=0;
    int flag_end=0;
     int *ptr_count_result;
   
    int res_count=0;

    ptr_count_result=&res_count;
    
    while(1)
    {

        ch=fgetc(fp);
        if(ch==EOF){
            break;
        }
        content[count]=ch;
        count++;
    }

    stack dde;
    stack *de;
    de=&dde;
    dde.counter=0;
    int space_count;
    int first_pass_flag=0;
    int in_count=0;//aux length
    int first_time_flag=0;
    for(int i=0;i<count;i++)
    
    {   
        if(content[i]=='<')
        {

        int check_Signature;

        check_Signature=isSignature(content+i);
        if(check_Signature==0)
        {  // printf("\nfound start of signed info\n");
            int k=11;
            while(content[k+i]!='>')
            {
                aux_copy[k-11]=content[k+i];
                k++;
                in_count++;

            }
            aux_copy[k]='\0';
          //  printf("%s\n",aux_copy);
            flag_ini=1;
        }

        if(check_Signature==2)
        {
            //end()
           // printf("\njhghggg\n");
            flag_end=1;
            for(int f=0;f<13;f++)
            {
            res[res_count]=content[i+f];
            res_count++;
            }
        }

        if(check_Signature==3)
        {
           // content[i+12]=' ';
            space_count=aux_space_count;
            for(int o=0;o<11;o++)
            {
                res[res_count]=content[i+o];
              //  printf("%c",res[res_count]);
                res_count++;
            }
            i=i+12;
            res[res_count]=' ';
            res_count++;

            for(int j=0;j<in_count;j++)
            {
                res[res_count]=aux_copy[j];
              //  printf("%c",res[res_count]);
                res_count++;
            }
            res[res_count]='>';
            res_count++;
            res[res_count]='\n';
            res_count++;
            
            first_pass_flag=1;
        }
        }

        if(flag_ini==1 && first_pass_flag==1 && flag_end!=1)
        {
            if(first_time_flag==0){
                first_time_flag=1;
                space_count=space_count+4;
                for(int y=0;y<space_count;y++)
                {
                    res[res_count]=space;
                    res_count++;
                }
            }
            
            if(content[i]=='<')
            {
                if(content[i+1]!='/')
                {  
                    updateStack_add(content,i,de);
                    space_count=space_count+2;
                }
                if(content[i+1]=='/' && content[i-1]!='>')
                {
                    
                    updateStack_remove(content+i,de);
                   /*  printf("\nprinting stack::\n");
                    for(int i=0;i<de->counter;i++){
                        printf("%s ",de->list_att[i]);
                    }
                    printf("\n\n");*/
                    space_count=space_count-2;   
                }
              //  printf("\npassed updatestack\n");
              
            }

            if(content[i]=='/' && content[i+1]=='>')
                {

                    replaceTag(content+i,de,res,ptr_count_result);
                    space_count=space_count-2;
                
                }else{

              //  printf("%c",content[i]);
                res[res_count]=content[i];
                res_count=res_count+1;
                }

            if(content[i]=='>' && content[i+1]=='<')
            {   
                printf("\n");//new line 

                res[res_count]=0x0a;//'\n';

                res_count=res_count+1;

            
                if(content[i+2]=='/')
                {
                    updateStack_remove(content+i,de);
                  /*  printf("\nprinting stack::\n");
                    for(int i=0;i<de->counter;i++){
                        printf("%s ",de->list_att[i]);
                    }
                    printf("\n\n");*/
                     space_count=space_count-2;
                }
                
                for(int a=0;a<space_count;a++)
                {
                   // printf("%c",space);
                    res[res_count]=space;
                    res_count=res_count+1;
                }      
            


            }

    
        }

    }
    free(content);
    fclose(fp);
    


}


int main(){
   
    char file_name[28]="permission_artifact_1.xml";
   
    char SignedInfo_canonilized[5000];

    char Reference_canonilized[5000];

    Reference_canon(file_name,Reference_canonilized);

    printf("\n\n");
    int y=0;
    while(Reference_canonilized[y]!='\0')
    {
       
       
        printf("%c",Reference_canonilized[y]);
      
        y++;

    }
    printf("\n");

    printf("space at Signature :: %d",aux_space_count);

    printf("\n");
    SignedInfo_canon(file_name,SignedInfo_canonilized);
     

    int gh=0;
    printf("\n");



     while(SignedInfo_canonilized[gh]!='\0'){
       
       
        printf("%c",SignedInfo_canonilized[gh]);
      
        gh++;

    }

    printf("\n");
    printf(" %d ",y);
    return 0;
}