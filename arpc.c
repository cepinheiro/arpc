/* $AISL: arpc.c,v1.3 Mon Jul  9 21:07:06 GMT 2001 cabeca Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>

#define VERSION "1.3"
#define MAXCHILDS 70
#define TIMEOUT 5
#define REFILE ".rpcr"
#define LOGFILE "LOG.RPCSCAN"
#define CFILE "RPC.CONFIG"

/* Prototypes */

void rpcs(char *);
void rscan(char *);
void scanF(int);
void scanA(u_short, u_short, u_short, u_short);
void scanB(u_short, u_short, u_short, u_short);
void scanC(u_short, u_short, u_short, u_short);
void child(char *);
void usage(char *);
void savef(int);
void stdins(void);
void printinfo(void);
void readconf(void);
void restore(void);

/* end */

typedef struct rpc_t
{
	u_long id;
	char *name;
}
rpc_t;

rpc_t vuln[64];

extern char *optarg;

u_short childs = 0;
u_short option = 0;

#ifdef _DEBUG_
u_long count = 0;
#endif

u_short a = 0;
u_short b = 0;
u_short c = 0;
u_short d = 0;

char ip[16];
char *sfile;

FILE *tolog;

int main(int argc, char *argv[])
{
	int opt = 0;

	signal(SIGINT, savef);
	signal(SIGQUIT, savef);
	signal(SIGKILL, savef);
	signal(SIGTERM, savef);
	signal(SIGHUP, SIG_IGN);

	readconf();

	if((tolog = fopen(LOGFILE, "a+")) == NULL)
	{
		fprintf(stderr, "Can't open log file %s: %s\n", LOGFILE, strerror(errno));
		exit(-1);
	}

	opt = getopt(argc, argv, "s:i:a:b:c:trh");

	switch(opt)
	{
		case 's':
		option = 0;
		rscan(optarg);
		break;
		case 'i':
		if ( argc < 3 )
		{
			usage(argv[0]);
			exit(1);
		}
		option = 1;
		sfile = optarg;
		scanF(0);
		break;
		case 'a':
		if ( argc < 3 )
		{
			usage(argv[0]);
			exit(1);
		}
		option = 2;
		a = atoi(strtok(optarg, "\0"));
		scanA(a,0,0,0);
		break;
		case 'b':
		if ( argc < 3 )
		{
			usage(argv[0]);
			exit(1);
		}
		option = 3;
		a = atoi(strtok(optarg, "."));
		b = atoi(strtok(NULL, "\0"));
		scanB(a,b,0,0);
		break;
		case 'c':
		if ( argc < 3 )
		{
			usage(argv[0]);
			exit(1);
		}
		option = 4;
		a = atoi(strtok(optarg, "."));
		b = atoi(strtok(NULL, "."));
		c = atoi(strtok(NULL, "\0"));
		scanC(a,b,c,0);
		break;
		case 't':
		option = 5;
		stdins();
		break;
		case 'r':
		restore();
		break;
		case 'h':
		usage(argv[0]);
		exit(1);
		break;
		default:
		usage(argv[0]);
		exit(1);
		break;
	}
	return 1;
}

void rpcs(char *host)
{
	struct sockaddr_in tos;
	struct pmaplist    *list;
	struct hostent     *hp;

	int i = 0;

	memset(&tos, 0x0, sizeof(struct sockaddr));

	if (( hp = gethostbyname(host)) == NULL)
	{
		if((tos.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE)
			exit(-1);
	}
	else
		memcpy(&(tos.sin_addr.s_addr), hp->h_addr, hp->h_length);

	tos.sin_family = AF_INET;
	tos.sin_port   = htons(PMAPPORT);

	signal(SIGALRM, SIG_DFL);
	alarm(TIMEOUT);
	list = pmap_getmaps(&tos);
	alarm(0);

	if (( list == NULL ))
		exit(-1);

	for ( ;list != NULL ; list = list->pml_next)
	{
		for (i = 0; vuln[i].id; i++)
		{
			if (list->pml_map.pm_prog == vuln[i].id)
			{
				if(list->pml_map.pm_prot == 6)
				{

					fprintf(tolog, "HOST: %s PROG: %s VER: %ld PORT: %ld(TCP)\n", host, vuln[i].name, list->pml_map.pm_vers, list->pml_map.pm_port);
#ifdef _DEBUG_
					printf("\rHOST: %s PROG: %s VER: %ld PORT: %ld(TCP)\n", host, vuln[i].name, list->pml_map.pm_vers, list->pml_map.pm_port);
#endif
				}
				else
				{
					fprintf(tolog, "HOST: %s PROG: %s VER: %ld PORT: %ld(UDP)\n", host, vuln[i].name, list->pml_map.pm_vers, list->pml_map.pm_port);
#ifdef _DEBUG_
					printf("\rHOST: %s PROG: %s VER: %ld PORT: %ld(UDP)\n", host, vuln[i].name, list->pml_map.pm_vers, list->pml_map.pm_port);
#endif
				}
				fflush(tolog);
				fflush(stdout);
			}
		}
	}
}

void rscan(char *host)
{
#ifdef _DEBUG_
	printf("Scanning %.200s... \n", host);
#endif
	rpcs(host);
#ifdef _DEBUG_
	printf("\nDone!\n");
#endif
}

void scanF(int rs)
{
	FILE *input = NULL;
	u_short w = 0;
	char tp[16];

	if (( input = fopen(sfile, "r")) == NULL)
	{
		fprintf(stderr, "Error opening input file %s: %s\n", sfile, strerror(errno));
		exit(-1);
	}

	if(rs == 1)
	{
		while((strcmp(tp, ip)) && (!feof(input)))
		{
			fgets(tp, 16, input);
			for(w=0;w<=strlen(tp);w++)
				if(tp[w] == 0x0a)
					tp[w] = 0x0;
			}
		}

		while(!feof(input))
		{
			fgets(ip, sizeof(ip), input);
			for(w = 0; w<= strlen(ip);w++)
				if(ip[w] == 0x0a)
					ip[w] = 0x0;
#ifdef _DEBUG_
				printinfo();
#endif
				child(ip);
			}
#ifdef _DEBUG_
			printf("\nDone! %ld hosts scanned.\n", count);
#endif
			fclose(input);
		}

		void scanA(u_short x, u_short w, u_short y, u_short z)
		{
			a = x;
			for(b=w;b <= 255;b++)
				for(c=y;c <= 255;c++)
					for(d=z;d <= 255;d++)
					{
						sprintf(ip, "%d.%d.%d.%d", a, b, c, d);
#ifdef _DEBUG_
						printinfo();
#endif
						child(ip);
					}
#ifdef _DEBUG_
					printf("\nDone! %ld hosts scanned.\n", count);
#endif
				}

				void scanB(u_short x, u_short w, u_short y, u_short z)
				{
					a = x;
					b = w;

					for (c = y ; c <= 255; c++ )
						for (d = z ; d <= 255; d++ )
						{
							sprintf(ip, "%d.%d.%d.%d", a, b, c, d);
#ifdef _DEBUG_
							printinfo();
#endif
							child(ip);
						}

#ifdef _DEBUG_
						printf("\nDone! %ld hosts scanned.\n", count);
#endif
					}

					void scanC(u_short x, u_short w, u_short y, u_short z)
					{
						a = x;
						b = w;
						c = y;

						for (d = z; d <= 255; d++ )
						{
							sprintf(ip, "%d.%d.%d.%d", a, b, c, d);
#ifdef _DEBUG_
							printinfo();
#endif
							child(ip);
						}
#ifdef _DEBUG_
						printf("\nDone! %ld hosts scanned.\n", count);
#endif
					}

					void stdins(void)
					{
						u_short w = 0;

						while(!feof(stdin))
						{
							fgets(ip, 16, stdin);
							for(w = 0; w <= strlen(ip);w++)
								if(ip[w] == 0x0a)
									ip[w] = 0x0;
#ifdef _DEBUG_
								printinfo();
#endif
								child(ip);
							}
#ifdef _DEBUG_
							printf("\nDone! %ld hosts scanned.\n", count);
#endif
						}

						void usage(char *progname)
						{
							printf("\n                    AISL - RPC SCANNER v"VERSION"\n\n");
							printf("Usage: %s <OPTION> [ARGUMENTS]\n",progname);
							printf("\tOptions:\n");
							printf("\t-s <hostname | ip>            - Scan a single host.\n");
							printf("\t-i <inputfile>                - Scan hosts from a file.\n");
							printf("\t-a <AAA>                      - Scan a class A block.\n");
							printf("\t-b <AAA.BBB>                  - Scan a class B block.\n");
							printf("\t-c <AAA.BBB.CCC>              - Scan a class C block.\n");
							printf("\t-t                            - Scan hosts from stdin.\n");
							printf("\t-r                            - Restore last scan.\n");
							printf("\t-h                            - Show this help message.\n\n");
						}

						void child(char *dest)
						{

							if ( childs >= MAXCHILDS )
							{
								(void) wait(NULL);
								--childs;
							}

							switch ( fork() )
							{
								case 0:
								rpcs(dest);
								exit(0);
								break;
								case -1:
								fprintf(stderr,"Error creating child: %s\n", strerror(errno));
								exit(-1);
								break;
								default:
								childs++;
								break;
							}
						}

						void savef(int s)
						{
							FILE *res = NULL;

							if(( res = fopen(REFILE, "w")) == NULL)
							{
								fprintf(stderr, "Error saving restore file: %s\n", strerror(errno));
								exit(-1);
							}

							fprintf(res, "%d:%s:%s\n", option, ip, sfile);
							putchar('\n');

							fclose(tolog);
							fclose(res);
							exit(1);
						}

#ifdef _DEBUG_
						void printinfo(void)
						{
							++count;
							fflush(stdout);
							printf("\rScanning %16s [ %ld ]", ip, count);
						}
#endif

						void readconf(void)
						{
							int x = 0;
							FILE *conf;
							char *ptr;
							char *read = (char*)malloc(1024);

#ifdef _DEBUG_
							printf("Opening configuration file... ");
#endif
							if((conf = fopen(CFILE, "r")) == NULL)
							{
								fprintf(stderr, "Can't open configuration file %s: %s\n", CFILE, strerror(errno));
								free(read);
								exit(-1);
							}
#ifdef _DEBUG_
							printf("Done.\nReading configuration... ");
#endif

							while(!feof(conf))
							{
								fgets(read, 1024, conf);
								ptr = strtok(read, ":");
								vuln[x].id = atoi(ptr);
								ptr = strtok(NULL, "\n");
								if(ptr)
									vuln[x++].name = strdup(ptr);
							}
							vuln[x+1].id = 0;

#ifdef _DEBUG_
							printf("Done. %d Records allocated!\n", x);
#endif
							free(read);
						}

						void restore(void)
						{
							char buf[128];
							int opt;
							char *ipp;
							FILE *rr;
							u_short m,n,o,p;

#ifdef _DEBUG_
							printf("Opening restore file... ");
#endif
							if((rr = fopen(REFILE, "r")) == NULL)
							{
								fprintf(stderr, "Cant open restore file %s: %s\n", REFILE, strerror(errno));
								exit(-1);
							}
#ifdef _DEBUG_
							printf("Done.\nReading it... ");
#endif
							fgets(buf, 128, rr);
							ipp = strtok(buf, ":");
							opt = atoi(ipp);
							ipp = strtok(NULL, ":");
							sfile = strtok(NULL, "\n");
							option = opt;
							strncpy(ip, ipp, strlen(ipp));
							m = atoi(strtok(ipp, "."));
							n = atoi(strtok(NULL, "."));
							o = atoi(strtok(NULL, "."));
							p = atoi(strtok(NULL, "\0"));

							switch(opt)
							{
								case 1:
#ifdef _DEBUG_
								printf("Done.\nRestarting scan from %s at ip %s\n", sfile, ip);
#endif
								scanF(1);
								break;
								case 2:
#ifdef _DEBUG_
								printf("Done.\nRestarting Class A scan at %s\n", ip);
#endif
								scanA(m, n, o, p);
								break;
								case 3:
#ifdef _DEBUG_
								printf("Done.\nRestarting Class B scan at %s\n", ip);
#endif
								scanB(m, n, o, p);
								break;
								case 4:
#ifdef _DEBUG_
								printf("Done.\nRestarting Class C scan at %s\n", ip);
#endif
								scanC(m, n, o, p);
								break;
							}
						}
