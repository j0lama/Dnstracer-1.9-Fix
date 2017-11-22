# Dnstracer-1.9-Fix
### dnstracer
dnstracer determines where a given Domain Name Server (DNS) gets its information from for a given hostname, and follows the chain of DNS servers back to the authoritative answer.

### Problem
Stack-based buffer overflow in dnstracer through 1.9 allows attackers to execute arbitrary code via a command line with a long name argument that is mishandled in a strcpy call for argv[0].

```
/*dnstracer_broken.h*/
#define NS_MAXDNAME	1024

/*dnstracer.c*/
strcpy(argv0, argv[0]);
```

### Fix
Check if argv[0] length is longer than 1024.

```
/*CVE-2017-9430 Fix*/
if(strlen(argv[0]) >= NS_MAXDNAME)
{
    free(server_ip);
    free(server_name);
    fprintf(stderr, "dnstracer: argument is too long %s\n", argv[0]);
    return 1;
}
```
