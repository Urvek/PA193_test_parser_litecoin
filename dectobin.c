# include <stdio.h>
# include <conio.h>
#include<math.h>

int main()
{long b[20], n, r, c = 0, i ; 
 scanf("%d",&n);
while(n > 0) 
 	{ 
 	 r = n % 2 ; 
     b[c] = r ; 
     n = n / 2 ; 
     c++ ; 
    } 
   printf("\nThe binary equivalent of %d is  ",n); 
   for(i = c - 1 ; i >= 0 ; i--) 
      printf("%ld", b[i]);
}
