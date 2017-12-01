#include<stdlib.h>
#include<stdio.h>
  int j;
  char *i;

void payload(){
  exit(244);
}


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

void lvl1(char *a){
  vulnerable(a);
}


int main(int argc, char *argv[]){
  int a;
  lvl1(argv[1]);
}
