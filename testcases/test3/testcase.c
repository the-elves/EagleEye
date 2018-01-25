#include<stdlib.h>
#include<stdio.h>

int vulnerable(char *s){
	printf ("hello %s",s);
}



int main(int argc, char *argv[]){
  int a;
  a=vulnerable(argv[1]);
}
