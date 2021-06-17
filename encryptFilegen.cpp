//this is the file to genrate publicPrivateinuse.txt file which will initially be installed in the rfm at the time of manufacturing 
// encrypting a file inside RFM and decrypting it.


#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"MP_INT.hpp"


using namespace std;

struct key{
char modulus[1000];
char private_exponent[1000];
};

int main()
{
    char RFM_private_key[700]="24021354375322558781058142276736617999389802434596138079632937453577588041977071136990155131350955784632074057774459381406055342415566243621056270140966629267130220147961070276489248399064064585487617556117107847879807603464052857723291974564966716033712609329726458163489658005940146657360121454440603066594695330718634482791509166056105316975123379501455703860598165895993179884232993174716442550760635024519308123321406513256918808853580242186763289628649427009957647963922327454796638500088631677702805825426368000585849292006901367973110968487920147218164610608698409129440488923014780703396073978252084600942649";

    char RFM_modulus[700]="26495127767604337655831691918113833077956334480395285962585476150242592943334533493300410596845191511956515492348526447864429111984398076478393159921716146324008099192785429713391158778980470576914436564260777828713503499078118282954851831718742193757807790192236071369965695862117529898068098551948463482032984966019192036825055149445334134853954472696975028748893285534653718791714099153590644093991103487859923770318942338310035808291238607889065040628342091199251953687656515817829870399170890472577591915379199888970387732102895345522222635522973211224211091186930411354449072698100145010326153546937615803429429";



char *content=(char*) malloc(sizeof(char)*5000);

char Content_Start[10]="<content>";
strcpy(content,Content_Start);
strcat(content,"\n");

char tag_private[20]="<PrivateKey=";
strcat(content,tag_private);
strcat(content,RFM_private_key);
strcat(content,">\n");

char tag_modulus[20]="<Modulus=";
strcat(content,tag_modulus);
strcat(content,RFM_modulus);
strcat(content,">\n");


char Content_End[12]="</content>";
strcat(content,Content_End);
strcat(content,"\0");
printf("The original file:\n%s\n",content);
////////////////once content is written then encrypt it 

// keys inside the drone to encrypt and decrypt data
    key Inside_RFM;
//    strcpy(Inside_RFM.modulus,"22276892195381124592167515112513415585546896199779662689852961263336225932003310046677212752641609554089643675451497029191199807830662280968178669257802876021582602957870426033036731149365245555942159313961523539342044560772214616537577142641426371781712526417060440710814088922616124381801854582276760039986941126696396693698716955526548439696481268378257904380799196075965524648088529760489079581705750188829594957267123661429085323800574567731644050980388441855957135397251575109761624893268517925837624338683168362002325002826985672771964638526535541406615525005973058572732361966636544780005532308101839286235841");
  //  strcpy(Inside_RFM.private_exponent,"21882592869097619022383815560649345486530548188858436379215772575030840850581764360207805138727877355747577565261470989643130903592086083615185897902094629745661584000165164971371982867734049668963919467703755144303565965619922492162283957334438645897604518259168103386485170248428494427991180439190548561792881347063935649786141952640907909996740374646108527271590040832916271121448579574017304441973269285201457696763287329891746177609260699109007988242160206776654971974188123190480891578777637418500288596991585947286827795077228833232767066601907106368396708634613409915226042936487417735312846480032804000008037");


strcpy(Inside_RFM.modulus,"180919775566931");
strcpy(Inside_RFM.private_exponent,"32102716896161");


int i=0;
char buf[50];
int aux;
mp_int public_key;
mp_read_radix(&public_key,"65537",10);//
mp_int private_key;
mp_read_radix(&private_key,Inside_RFM.private_exponent,10);//
mp_int modulus;
mp_read_radix(&modulus,Inside_RFM.modulus,10);//

char *encrypted_content=(char*) malloc(sizeof(char)*20000);
mp_int aux_int;
mp_int aux_int_result;
char snum[10];
while(content[i]!='\0'){
    aux=int(content[i]);
    sprintf(snum, "%d",aux );
    mp_read_radix(&aux_int, snum,10);
  // printf("\n %c  %d \n",content[i],aux);
    mp_exptmod(&aux_int,&private_key,&modulus,&aux_int_result);

    mp_to_decimal(&aux_int_result,buf,sizeof(buf));
  //  printf("\n modulus product==\n%s\n\n",buf);
  //  break;
   
    if(i==0){
    strcpy(encrypted_content,buf);
    strcat(encrypted_content,";");
    }else{
        strcat(encrypted_content,buf);
        strcat(encrypted_content,";");
    }
   


    i=i+1;
    
    
}
strcat(encrypted_content,"\0");


printf("\n The encrypted public key and private key:\n\n%s\n\n",encrypted_content);


///////////////////////// decrypting the file 
char *decrypted_content=(char*) malloc(sizeof(char)*6000);
char decrypt;
char buff2[30];
int j=0,k=0,first_pass=0,di=0;

while(encrypted_content[j]!='\0'){
    if(encrypted_content[j]!=';'){
        buff2[k]=encrypted_content[j];
        k++;
        j++;

    }else{
        buff2[k]='\0';

        mp_read_radix(&aux_int, buff2,10);
        mp_exptmod(&aux_int,&public_key,&modulus,&aux_int_result);
        mp_to_decimal(&aux_int_result,buf,sizeof(buf));
      // printf("\n modulus product==\n%s\n\n",buf);
        decrypt = atoi(buf);
        decrypted_content[di]=decrypt;
        di++;
        memset(buff2, 0, sizeof(buff2));
        k=0;
        
        j++;
    }


}
decrypted_content[di]='\0';
printf("\n\n\n%s\n",decrypted_content);



FILE *fptr;
fptr=fopen("PublicPrivateInuse.txt","w");
fprintf(fptr, "%s", encrypted_content);
fclose(fptr);


free(content);
free(encrypted_content);
free(decrypted_content);

return 0;
}