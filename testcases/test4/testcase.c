#include<stdlib.h>
#include<stdio.h>

void payload(){
  exit(244);
}


int vulnerable(char *str){
  char stack[4];

  char *j;
  char *i;

  i = str;
  j=stack;
  while(*i != '\0'){
    *j = *i;
    i++;
    j++;
  }
  return 1;

}


int main(int argc, char *argv[]){
  int a;
  a=vulnerable(argv[1]);
}
