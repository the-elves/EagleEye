int j;
char *i;
int vulnerable(char *str){
  char stack[2];
  i = str;
  j=0;
  while(*i != '\0'){
    *(stack+j) = *i;
    i++;
    j++;
  }
  return j;

}
int main(int argc, char *argv[]){
  int a;
  a = vulnerable(argv[1]);
}
