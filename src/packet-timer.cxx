// api includes
#include <pcapp/dnsreq.h>
#include<pcapp/timer/cifs_timer.h>
#include<pcapp/timer/dns_timer.h>
#include<pcapp/timer/ftp_timer.h>
#include<pcapp/timer/http_timer.h>
#include<pcapp/timer/mapi_timer.h>
#include<pcapp/timer/options.h>
#include<pcapp/timer/timeval.h>


// tp includes
#include <pcap.h>

// std includes
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#ifndef IP_HL
  #define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
  #define TH_OFF(th)  ((th)->th_x2)
  #define SIZE_ETHER  14
#endif

using namespace pcapp::timer;



HTTPTimer *cur_http_timer = NULL;
DNSTimer  *cur_dns_timer  = NULL;
FTPTimer  *cur_ftp_timer  = NULL;
CIFSTimer *cur_cifs_timer  = NULL;
MAPITimer *cur_mapi_timer  = NULL;



/*
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
  int i;
  int gap;
  const u_char *ch;

  printf("%05d   ", offset);

  ch = payload;
  for(i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    // print extra space after 8th
    if (i == 7)
      printf(" ");
  }
  if (len < 8)
    printf(" ");

  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  ch = payload;
  for(i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}

void print_tcpflags(const tcphdr *tcph)
{
  if(tcph->urg)
  { printf("U"); }
  else
  { printf(" "); }
  if(tcph->ack)
  { printf("A"); }
  else
  { printf(" "); }
  if(tcph->psh)
  { printf("P"); }
  else
  { printf(" "); }
  if(tcph->rst)
  { printf("R"); }
  else
  { printf(" "); }
  if(tcph->syn)
  { printf("S"); }
  else
  { printf(" "); }
  if(tcph->fin)
  { printf("F"); }
  else
  { printf(" "); }
}

void print_payload(const u_char *payload, int len)
{
  int len_rem = len;
  int line_width = 16;
  int line_len;
  int offset = 0;
  const u_char *ch = payload;

  if (len <= 0)
    return;

  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  for ( ;; ) {
    line_len = line_width % len_rem;
    print_hex_ascii_line(ch, line_len, offset);
    len_rem = len_rem - line_len;
    ch = ch + line_len;
    offset = offset + line_width;
    if (len_rem <= line_width) {
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}
*/

//#############################################################################
int handle_http(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);
    
    if(cur_http_timer == NULL)
    {
        cur_http_timer = new HTTPTimer("Other");
    }

    cur_http_timer->handleData(opts, pkthdr, packet);

    return 1;
}

//#############################################################################
int handle_dns(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);
    
    if(cur_dns_timer == NULL)
    {
        cur_dns_timer = new DNSTimer(opts->label);
    }
    
    cur_dns_timer->handleData(opts, pkthdr, packet);
    return 1;
}

//#############################################################################
int handle_ftp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);

    if(cur_ftp_timer==NULL)
    {
      cur_ftp_timer = new FTPTimer("All");
    }

    cur_ftp_timer->handleData(opts, pkthdr, packet);
    return 1;
}    

//#############################################################################
int handle_cifs(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);

    if(cur_cifs_timer==NULL)
    {
      cur_cifs_timer = new CIFSTimer("All");
    }

    cur_cifs_timer->handleData(opts, pkthdr, packet);
    return 1;
}    

//#############################################################################
int handle_mapi(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);

    if(cur_mapi_timer==NULL)
    {
      cur_mapi_timer = new MAPITimer("All");
    }

    cur_mapi_timer->handleData(opts, pkthdr, packet);
    return 1;
}

//#############################################################################
int handle_udp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  const ip *iph=(ip*)(packet+14);
  const udphdr *udph;
  int size_ip;

  size_ip = IP_HL(iph)*4;
  udph=(udphdr*)(packet+SIZE_ETHER+size_ip);

  if((ntohs(udph->dest) == 53) || ntohs(udph->source) == 53)
  {
    handle_dns(args,pkthdr,packet);
  }
  return 1;
}

//#############################################################################
int handle_tcp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  Options *opts = (Options*)(args);

  if (strcmp(opts->protocol,"HTTP")==0 || strcmp(opts->protocol,"REST")==0 || 
      strcmp(opts->protocol,"GET(REST)")==0 || strcmp(opts->protocol,"POST(REST)")==0 || 
      strcmp(opts->protocol,"WebWalk")==0)
  {
    handle_http(args,pkthdr,packet);
  }
  else if (strcmp(opts->protocol,"CIFS")==0)
  {
    handle_cifs(args,pkthdr,packet);
  }
  else if (strcmp(opts->protocol,"FTP")==0)
  {
    handle_ftp(args,pkthdr,packet);
  }
  else if (strcmp(opts->protocol,"MAPI")==0)
  {
    handle_mapi(args,pkthdr,packet);
  }

  return 1;
}

//#############################################################################
void my_callback(u_char *args,const pcap_pkthdr* pkthdr,const u_char* packet)
{
  const ip *iph=(ip*)(packet+sizeof(ether_header));

  if (iph->ip_p == IPPROTO_TCP)
  {
    handle_tcp(args, pkthdr,packet);
  }
  else if (iph->ip_p == IPPROTO_UDP)
  {
    handle_udp(args,pkthdr,packet);
  }
}

//#############################################################################
int main(int argc,char **argv)
{
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    Options opts = {"","",{0}};
    char selfip[INET_ADDRSTRLEN];
    ifaddrs *ifaddrstruct=NULL,*tmpaddr;

    if(argc < 2)
    {
        fprintf(stdout,"Usage: %s <label> <protocol> <\"filters\">\n",argv[0]);
        return 0;
    }

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
      printf("%s\n",errbuf);
      exit(1);
    }

    printf("Looked up our Dev\n");

    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    printf("Looked up our Net\n");

    getifaddrs(&ifaddrstruct);
    tmpaddr = ifaddrstruct;
    while (ifaddrstruct!=NULL)
    {
      if(ifaddrstruct->ifa_addr->sa_family==AF_INET && strcmp(ifaddrstruct->ifa_name,dev)==0)
      {
        opts.selfaddr=((sockaddr_in *)ifaddrstruct->ifa_addr)->sin_addr;
      }
      ifaddrstruct=ifaddrstruct->ifa_next;
    }
    freeifaddrs(tmpaddr);

    printf("Looked up our self-addr\n");

    inet_ntop(AF_INET,(const void*)&opts.selfaddr,selfip,INET_ADDRSTRLEN);

    descr = pcap_open_live(dev,BUFSIZ,1,2000,errbuf);
    if(descr == NULL)
    {
      printf("pcap_open_live(): %s\n",errbuf);
      exit(1);
    }

    printf("did a pcap open live()\n");

    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[3],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        printf("Compiled pcap program\n");
        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }

    printf("Setting up Options\n");
    strncpy(opts.label,   argv[1],strlen(argv[1]));
    strncpy(opts.protocol,argv[2],strlen(argv[2]));

    printf("Entering Loop\n");
    pcap_loop(descr,-1,my_callback,(u_char*)&opts);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
