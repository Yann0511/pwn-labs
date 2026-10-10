#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Goal : Force the program to execute a shell
*/

typedef void (*resultfn_t)(char *arg);
void auth_ok(char *user){
	printf("Authentication success for user '%s'\n", user);
}
void auth_nok(char *user){
	printf("Authentication failed for user '%s'\n", user);
}

int check_login(void)
{
	// FIXME
	return 0;
}

int doit(char *u)
{
	resultfn_t fn = auth_nok;	
	char username[64];
	strcpy(username, u);
	if(check_login())
	{
		fn = auth_ok;
	}
	fn(u);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s <username>\n", *argv);
		return 0;
	}
	system("date");
	doit(argv[1]);
	return 0;
}
