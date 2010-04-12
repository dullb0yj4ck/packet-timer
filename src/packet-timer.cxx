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

#include <pcap.h>
#include "dnsreq.h"

#define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
#define TH_OFF(th)  ((th)->th_x2)
#define SIZE_ETHER  14

class options {
public:
    char label[256];
    char protocol[256];
    in_addr selfaddr;
};

class dnstimer {
public:
    char label[256];
    unsigned short id;
    timeval start;
    timeval auth;
};

class httptimer {
public:
    char label[256];
    timeval start;
    timeval send;
    timeval ack;
    timeval recv;
    timeval end;
};

class ftptimer {
public:
    char label[256];
    timeval start;
    timeval ack;
    timeval cmd;
    timeval end;
};

class cifstimer {
public:
    char label[256];
    timeval start;
    timeval ack;
    timeval send72;
    timeval recv72;
    timeval send73;
    timeval recv73;
    timeval sendtree;
    timeval recvtree;
    timeval fin;
};

class mapitimer {
public:
    char label[256];
    timeval start;
    timeval ack;
    timeval end;
    timeval dce1streq;
    timeval dce1stresp;
    timeval newdcechain;
    timeval dcechainclose;
    int chaincount;
    long unsigned int chain_duration;
};



httptimer *cur_http_timer = NULL;
dnstimer  *cur_dns_timer  = NULL;
ftptimer  *cur_ftp_timer  = NULL;
cifstimer *cur_cifs_timer  = NULL;
mapitimer *cur_mapi_timer  = NULL;

mapitimer* new_mapi_timer(const char* label)
{
  mapitimer *tm = (mapitimer*)malloc(sizeof(mapitimer));
  if(tm==NULL)
  {
    return NULL;
  }
  strncpy(tm->label,label,strlen(label));
  tm->start.tv_sec=0;tm->start.tv_usec=0;
  tm->ack.tv_sec=0;tm->ack.tv_usec=0;
  tm->dce1streq.tv_sec=0;tm->dce1streq.tv_usec=0;
  tm->dce1stresp.tv_sec=0;tm->dce1stresp.tv_usec=0;
  tm->newdcechain.tv_sec=0;tm->newdcechain.tv_usec=0;
  tm->dcechainclose.tv_sec=0;tm->dcechainclose.tv_usec=0;
  tm->chaincount = 0;
  return tm;
}

httptimer* new_http_timer(const char* label)
{
  httptimer *tm = (httptimer*)malloc(sizeof(httptimer));
  if(tm==NULL)
  {
    return NULL;
  }
  strncpy(tm->label,label,strlen(label));
  tm->start.tv_sec=0;tm->start.tv_usec=0;
  tm->ack.tv_sec=0;tm->ack.tv_usec=0;
  tm->recv.tv_sec=0;tm->recv.tv_usec=0;
  tm->end.tv_sec=0;tm->end.tv_usec=0;
  tm->send.tv_sec=0;tm->send.tv_usec=0;
  return tm;
}

ftptimer* new_ftp_timer(const char* label)
{
  ftptimer *tm = (ftptimer*)malloc(sizeof(ftptimer));
  if(tm==NULL)
  {
    return NULL;
  }
  strncpy(tm->label,label,strlen(label));
  tm->start.tv_sec=0;tm->start.tv_usec=0;
  tm->ack.tv_sec=0;tm->ack.tv_usec=0;
  tm->cmd.tv_sec=0;tm->cmd.tv_usec=0;
  tm->end.tv_sec=0;tm->end.tv_usec=0;
  return tm;
}

dnstimer* new_dns_timer(const char* label)
{
  dnstimer *tm=(dnstimer*)malloc(sizeof(dnstimer));
  if (tm==NULL)
  {
    return NULL;
  }

  strncpy(tm->label,label,strlen(label));
  tm->start.tv_sec=0; tm->start.tv_usec=0;
  tm->auth.tv_sec=0; tm->auth.tv_usec=0;
  return tm;
}

cifstimer* new_cifs_timer(const char* label)
{
  cifstimer *tm=(cifstimer*)malloc(sizeof(cifstimer));
  if (tm==NULL)
  {
    return NULL;
  }

  strncpy(tm->label,label,strlen(label));
  tm->start.tv_sec=0; tm->start.tv_usec=0;
  tm->ack.tv_sec=0; tm->ack.tv_usec=0;
  tm->fin.tv_sec=0; tm->fin.tv_usec=0;
  tm->send72.tv_sec=0; tm->send72.tv_usec=0;
  tm->recv72.tv_sec=0; tm->recv72.tv_usec=0;
  tm->send73.tv_sec=0; tm->send73.tv_usec=0;
  tm->recv73.tv_sec=0; tm->recv73.tv_usec=0;
  tm->sendtree.tv_sec=0; tm->sendtree.tv_usec=0;
  tm->recvtree.tv_sec=0; tm->recvtree.tv_usec=0;
  return tm;
}

/* from the glibc manual */
int timeval_subtract (timeval *result, timeval *x, timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

int print_http_timings(options *opts,httptimer *tm)
{
  timeval tmp;
  char timestr[64];
  timeval_subtract(&tmp,&(tm->ack),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|%s|Time to First ACK\t%s\n",opts->protocol,tm->label,timestr);

  timeval_subtract(&tmp,&(tm->send),&(tm->ack));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|%s|Ack to First Send\t%s\n",opts->protocol,tm->label,timestr);

  timeval_subtract(&tmp,&tm->recv,&tm->send);
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|%s|Send to First Recv\t%s\n",opts->protocol,tm->label,timestr);

  timeval_subtract(&tmp,&tm->end,&tm->recv);
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|%s|Recv to Connection Close\t%s\n",opts->protocol,tm->label,timestr);
  return 1;
}

int dns_q_to_str(const char* dns,char* str)
{
  char x=dns[0];
  const char *pt=dns;
  char size=0;

  while (x != 0)
  {
    if(size>0)
    {
      strcat(str,".");
      size++;
    }
    strncpy(str+size,pt+1,x);
    size+=x;
    pt += x+1;
    x=pt[0];
  }
  return 1;
}

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
    /* print extra space after 8th */
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

int handle_http(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  const ether_header *ethh;
  const ip *iph;
  const tcphdr *tcph;
  const timeval ts = pkthdr->ts;
  options *opts = (options*)(args);
  int size_ip;
  int size_tcp;
  int size_payload;
  const char *payload;


  ethh=(ether_header*)(packet);
  iph=(ip*)(packet+14); /* sizeof(ether_header) */
  size_ip = IP_HL(iph)*4;
  tcph = (tcphdr*)(packet+SIZE_ETHER+size_ip);
  size_tcp= tcph->doff*4;

  payload=(const char *)(packet + SIZE_ETHER + size_ip + size_tcp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);
 
  if((tcph->syn) && !(tcph->ack) && (size_payload == 0) && (opts->selfaddr.s_addr != iph->ip_dst.s_addr))
  {
    if(cur_http_timer==NULL)
    {
      cur_http_timer = new_http_timer("Other");
      cur_http_timer->start = ts;
    }
  }

  if((size_payload == 0) && (tcph->ack) && !(tcph->syn) && (opts->selfaddr.s_addr != iph->ip_dst.s_addr))
  {
    if(cur_http_timer != NULL && cur_http_timer->ack.tv_sec == 0)
    {
      cur_http_timer->ack = ts;
    }
  }

  else if(strncmp(payload,"GET ",4)==0 && cur_http_timer->send.tv_sec == 0)
  {
    strcpy(cur_http_timer->label,"GET");
    cur_http_timer->send = ts;
  }

  else if(strncmp(payload,"PUT ",4)==0 && cur_http_timer->send.tv_sec == 0)
  {
    strcpy(cur_http_timer->label,"PUT");
    cur_http_timer->send = ts;
  }

  else if(strncmp(payload,"POST ",5)==0 && cur_http_timer->send.tv_sec == 0)
  {
    strcpy(cur_http_timer->label,"POST");
    cur_http_timer->send = ts;
  }

  else if ((strncmp(payload,"HTTP/1.",7)==0) && (opts->selfaddr.s_addr == iph->ip_dst.s_addr)
      && cur_http_timer->recv.tv_sec == 0)
  {
    if(cur_http_timer != NULL && cur_http_timer->recv.tv_sec == 0)
    {
      cur_http_timer->recv = ts;
    }
  }

  else if(tcph->fin)
  {
    if(cur_http_timer != NULL && cur_http_timer->end.tv_sec == 0)
    {
      cur_http_timer->end = ts;
      print_http_timings(opts,cur_http_timer);
      free(cur_http_timer);
      cur_http_timer=NULL;
    }
  }

  return 1;
}

int print_dns_timings(options *opts,dnstimer *tm)
{
  timeval tmp;
  char timestr[64];
  timeval_subtract(&tmp,&(tm->auth),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|DNS|Total Time\t%s\n",opts->protocol,timestr);

  return 1;
}

int handle_dns(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  const ether_header *ethh;
  const ip *iph;
  const udphdr *udph;
  const timeval ts = pkthdr->ts;
  const dns_header *dnsh;
  options *opts = (options*)(args);
  int size_ip;
  int size_udp;
  int size_payload;
  const char *payload;
  const char *req_dns_str;
  char req_str[1024] = "";

  ethh=(ether_header*)(packet);
  iph=(ip*)(packet+14); /* sizeof(ether_header) */
  size_ip = IP_HL(iph)*4;
  size_udp = 8;

  udph=(udphdr*)(packet+SIZE_ETHER+size_ip);

  payload=(const char *)(packet + SIZE_ETHER + size_ip + size_udp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_udp);

  dnsh = (dns_header*)(payload);

  if (dnsh->qr == 0)
  {
    req_dns_str=payload+12;
    dns_q_to_str(req_dns_str,req_str);
    if (strcmp(req_str,opts->label)==0)
    {
      cur_dns_timer = new_dns_timer(opts->label);
      cur_dns_timer->id = dnsh->id;
      cur_dns_timer->start = ts;
    }
  }
  if ((dnsh->qr == 1) && (dnsh->ancount > 0))
  {
    if (cur_dns_timer != NULL && cur_dns_timer->start.tv_sec != 0 && dnsh->id == cur_dns_timer->id)
    {
      cur_dns_timer->auth = ts;
      print_dns_timings(opts,cur_dns_timer);
      free(cur_dns_timer);
      cur_dns_timer=NULL;
    }
  }
  return 1;
}

int print_ftp_timings(options *opts,ftptimer *tm)
{
  timeval tmp;
  char timestr[64];
  timeval_subtract(&tmp,&(tm->ack),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|All|Time to First ack\t%s\n",opts->protocol,timestr);

  timeval_subtract(&tmp,&(tm->end),&(tm->ack));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|All|Ack to QUIT Message\t%s\n",opts->protocol,timestr);
  return 1;
}

int handle_ftp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  const ether_header *ethh;
  const ip *iph;
  const tcphdr *tcph;
  const timeval ts = pkthdr->ts;
  options *opts = (options*)(args);
  int size_ip;
  int size_tcp;
  int size_payload;
  const char *payload;

  ethh=(ether_header*)(packet);
  iph=(ip*)(packet+14); /* sizeof(ether_header) */
  size_ip = IP_HL(iph)*4;
  tcph = (tcphdr*)(packet+SIZE_ETHER+size_ip);
  size_tcp= tcph->doff*4;

  payload=(const char *)(packet + SIZE_ETHER + size_ip + size_tcp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);

  if((tcph->syn) && !(tcph->ack) && (size_payload == 0))
  {
    if(cur_ftp_timer==NULL)
    {
      cur_ftp_timer = new_ftp_timer("All");
      cur_ftp_timer->start = ts;
    }
  }

  else if((size_payload == 0) && (tcph->ack) && !(tcph->syn) && (opts->selfaddr.s_addr == iph->ip_dst.s_addr))
  {
    if(cur_ftp_timer != NULL && cur_ftp_timer->ack.tv_sec == 0)
    {
      cur_ftp_timer->ack = ts;
    }
  }
  else if((opts->selfaddr.s_addr == iph->ip_dst.s_addr) && strncmp(payload,"221 ",4)==0)
  {
    if(cur_ftp_timer != NULL && cur_ftp_timer->end.tv_sec ==0)
    {
      cur_ftp_timer->end = ts;
      print_ftp_timings(opts,cur_ftp_timer);
      free(cur_ftp_timer);
      cur_ftp_timer = NULL;
    }
  }

  return 1;
}


int print_cifs_timings(options *opts,cifstimer *tm)
{
  timeval tmp;
  long unsigned int a,b;
  char timestr[64];

  timeval_subtract(&tmp,&(tm->ack),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|All|Time to first ACK\t%s\n",opts->protocol,timestr);

  a=tm->recv72.tv_sec*1000000 + tm->recv72.tv_usec;
  b=tm->send72.tv_sec*1000000 + tm->send72.tv_usec;

  if(a>b)
  {
    timeval_subtract(&tmp,&(tm->send72),&(tm->ack));
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|All|ACK to First Command Recv\t%s\n",opts->protocol,timestr);

    timeval_subtract(&tmp,&(tm->recv72),&(tm->send72));
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|All|Command Recv to First Command Send\t%s\n",opts->protocol,timestr);

    timeval_subtract(&tmp,&(tm->fin),&(tm->recv72));
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|All|Command Recv to Connection End\t%s\n",opts->protocol,timestr);
  }
  else
  {
    timeval_subtract(&tmp,&(tm->recv72),&(tm->ack));
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|All|ACK to First Command Recv\t%s\n",opts->protocol,timestr);

    timeval_subtract(&tmp,&(tm->send72),&(tm->recv72));
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|All|Command Recv to First Command Send\t%s\n",opts->protocol,timestr);

    timeval_subtract(&tmp,&(tm->fin),&(tm->send72));
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|All|Command Recv to Connection End\t%s\n",opts->protocol,timestr);
  }


  return 1;
}

int handle_cifs(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  const ether_header *ethh;
  const ip *iph;
  const tcphdr *tcph;
  const timeval ts = pkthdr->ts;
  options *opts = (options*)(args);
  int size_ip;
  int size_tcp;
  int size_payload;
  char incoming;
  const char *payload;
  const char *smbptr;

  ethh=(ether_header*)(packet);
  iph=(ip*)(packet+14); /* sizeof(ether_header) */
  size_ip = IP_HL(iph)*4;
  tcph = (tcphdr*)(packet+SIZE_ETHER+size_ip);
  size_tcp= tcph->doff*4;

  payload=(const char *)(packet + SIZE_ETHER + size_ip + size_tcp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);

  if(opts->selfaddr.s_addr == iph->ip_dst.s_addr)
  { incoming = 1;} 
  else 
  { incoming = 0;} 

  if((tcph->syn) && !(tcph->ack) && (size_payload == 0) && (! incoming))
  {
    if(cur_cifs_timer==NULL)
    {
      cur_cifs_timer = new_cifs_timer("All");
      cur_cifs_timer->start = ts;
    }
  }

  if((size_payload == 0) && (tcph->ack) && !(tcph->syn) && (! incoming))
  {
    if(cur_cifs_timer != NULL && cur_cifs_timer->ack.tv_sec == 0)
    {
      cur_cifs_timer->ack = ts;
    }
  }

  if((size_payload > 0) && (! incoming))
  {
    smbptr = &(payload[5]);
    if((strncmp(smbptr,"SMB",3)==0) &&( payload[8] == 0x72))
    {
      if(cur_cifs_timer != NULL && cur_cifs_timer->send72.tv_sec == 0)
      {
        cur_cifs_timer->send72 = ts;
      }
    }
  }

  if((size_payload > 0) && (incoming))
  {
    smbptr = &(payload[5]);
    if((strncmp(smbptr,"SMB",3)==0) &&( payload[8] == 0x72))
    {
      if(cur_cifs_timer != NULL && cur_cifs_timer->recv72.tv_sec == 0)
      {
        cur_cifs_timer->recv72 = ts;
      }
    }
  }

  if((size_payload == 0) && (tcph->fin) && (tcph->ack) && (!incoming))
  {
    if(cur_cifs_timer != NULL && cur_cifs_timer->fin.tv_sec == 0)
    {
      cur_cifs_timer->fin = ts;
      print_cifs_timings(opts,cur_cifs_timer);
      free(cur_cifs_timer);
      cur_cifs_timer = NULL;
    }
  }

  return 1;
}

int print_mapi_timings(options *opts,mapitimer *tm)
{
  timeval tmp;
  //double avg_chain;
  char timestr[64];

  timeval_subtract(&tmp,&(tm->ack),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|Protocol|%s|Time|Exchange|Time to First ACK\t%s\n",opts->protocol,timestr);

  timeval_subtract(&tmp,&(tm->dce1streq),&(tm->ack));
  if(tmp.tv_sec > 0)
  {
    snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
    printf("Net|Protocol|%s|Time|Exchange|Time to First RPC Request\t%s\n",opts->protocol,timestr);
  }

  /*avg_chain = (double)tm->chain_duration / (double)tm->chaincount / 1000000.0;*/
  /*printf("Net|Protocol|%s|Time|Exchange|Avg. MAPI RPC Connection\t%lf\n",opts->protocol,avg_chain);*/

  return 1;
}

int handle_mapi(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  const ether_header *ethh;
  const ip *iph;
  const tcphdr *tcph;
  const timeval ts = pkthdr->ts;
  options *opts = (options*)(args);
  int size_ip;
  int size_tcp;
  int size_payload;
  char incoming;
  const char *payload;
  //long unsigned int begin,end;

  ethh=(ether_header*)(packet);
  iph=(ip*)(packet+14); /* sizeof(ether_header) */
  size_ip = IP_HL(iph)*4;
  tcph = (tcphdr*)(packet+SIZE_ETHER+size_ip);
  size_tcp= tcph->doff*4;

  payload=(const char *)(packet + SIZE_ETHER + size_ip + size_tcp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);

  if(opts->selfaddr.s_addr == iph->ip_dst.s_addr)
  { incoming = 1;} 
  else 
  { incoming = 0;} 


  if(!incoming && size_payload==0 && tcph->syn && (! tcph->ack))
  {
    if((cur_mapi_timer == NULL) || (cur_mapi_timer->start.tv_sec ==0))
    {
      cur_mapi_timer = new_mapi_timer("Exchange\0");
      cur_mapi_timer->start = ts;
    }
  }
  if(!incoming && size_payload==0 && tcph->ack && (! tcph->syn))
  {
    if((cur_mapi_timer != NULL) && (cur_mapi_timer->ack.tv_sec==0))
    {
      cur_mapi_timer->ack=ts;
    }
  }
  if(size_payload > 0 && payload[0] == 0x05 && payload[1] == 0x00
      && payload[48] == 0x01 && cur_mapi_timer != NULL)
  {

    cur_mapi_timer->chaincount++;
    cur_mapi_timer->newdcechain = ts;
    if(cur_mapi_timer->dce1streq.tv_sec==0)
    {
      cur_mapi_timer->dce1streq=ts;
    }
    else if(cur_mapi_timer->dce1stresp.tv_sec ==0)
    {
      cur_mapi_timer->dce1stresp=ts;
    }
  }
  if(! incoming && size_payload == 0 && (tcph->fin) && (ntohs(tcph->source) != 135)&& (ntohs(tcph->source) != 135 ) && cur_mapi_timer != NULL)
  {
    /*begin=cur_mapi_timer->newdcechain.tv_sec*1000000 + cur_mapi_timer->newdcechain.tv_usec;*/
    /*end = (ts.tv_sec*1000000+ts.tv_usec) - begin;*/
    /*(cur_mapi_timer->chain_duration) += end;*/
    print_mapi_timings(opts,cur_mapi_timer);
    free(cur_mapi_timer);
    cur_mapi_timer=NULL;
  }
  return 1;
}

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

int handle_tcp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
  options *opts = (options*)(args);

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

int main(int argc,char **argv)
{
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    options opts = {"","",{0}};
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

    printf("Setting up options\n");
    strncpy(opts.label,   argv[1],strlen(argv[1]));
    strncpy(opts.protocol,argv[2],strlen(argv[2]));

    printf("Entering Loop\n");
    pcap_loop(descr,-1,my_callback,(u_char*)&opts);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
