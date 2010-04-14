/*
 * Copyright (C) 2000-2004 Absolute Performance, Inc.
 * All Rights Reserved
 *
 * THIS IS PROPRIETARY SOFTWARE DEVELOPED FOR THE SYSSHEP PROJECT AT
 * ABSOLUTE PERFORMANCE, INC.; IT MAY NOT BE DISCLOSED TO THIRD PARTIES,
 * COPIED OR DUPLICATED IN ANY FORM, IN WHOLE OR IN PART, WITHOUT THE PRIOR
 * WRITTEN PERMISSION OF ABSOLUTE PERFORMANCE, INC.
 *
 * FURTHERMORE, THIS SOFTWARE IS DISTRIBUTED AS IS, AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NOT EVENT SHALL ABSOLUTE PERFORMANCE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE AND OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.  RECEIVING PARTY MAY NOT REVERSE ENGINEER, DECOMPILE OR
 * DISASSEMBLE ANY SOFTWARE DISCLOSED TO RECEIVING PARTY.
 *
 */


// class header
#include<pcapp/timer/cifs_timer.h>

// api includes
#include <pcapp/dnsreq.h>

// tp includes
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// std includes
#include<cstring>
#include<iostream>

// use own class's namespace
using namespace pcapp::timer;
using namespace pcapp;

//#############################################################################
/***************************** public interface ******************************/
//#############################################################################

#ifndef IP_HL
  #define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
  #define TH_OFF(th)  ((th)->th_x2)
  #define SIZE_ETHER  14
#endif

//#############################################################################
CIFSTimer::CIFSTimer(const std::string & aLabel)
    :
    _Label(aLabel),
    _StartTime(),
    _AckTime(),
    _Send72Time(),
    _Recv72Time(),
    _Send73Time(),
    _Recv73Time(),
    _SendTreeTime(),
    _RecvTreeTime(),
    _FinTime()
{
}

//#############################################################################
void 
CIFSTimer::handleData(Options *opts,
                      const pcap_pkthdr* pkthdr,
                      const u_char* packet)
{
    const ether_header *ethh;
    const ip *iph;
    const tcphdr *tcph;
    const timeval ts = pkthdr->ts;
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
    {
        incoming = 1;
    } 
    else 
    {
        incoming = 0;
    } 

    
    if((tcph->syn) && !(tcph->ack) && (size_payload == 0) && (! incoming))
    {
        _Label =  "All";
        _StartTime = ts;
    }
    
    if((size_payload == 0) && (tcph->ack) && !(tcph->syn) && (! incoming))
    {
        if(_AckTime.tv_sec == 0)
        {
            _AckTime = ts;
        }
    }
    
    if((size_payload > 0) && (! incoming))
    {
        smbptr = &(payload[5]);
        if((strncmp(smbptr,"SMB",3)==0) &&( payload[8] == 0x72))
        {
            if(_Send72Time.tv_sec == 0)
            {
                _Send72Time = ts;
            }
        }
    }
    
    if((size_payload > 0) && (incoming))
    {
        smbptr = &(payload[5]);
        if((strncmp(smbptr,"SMB",3)==0) &&( payload[8] == 0x72))
        {
            if(_Recv72Time.tv_sec == 0)
            {
                _Recv72Time = ts;
            }
        }
    }
    
    if((size_payload == 0) && (tcph->fin) && (tcph->ack) && (!incoming))
    {
        // if start time not set, we started sniffing in the middle of a
        // request.  Ignore this one.
        if(_FinTime.tv_sec == 0 && _StartTime.isSet())
        {
            _FinTime = ts;
            printTimings(*opts);
        }
        
        _Label = "";
        _StartTime.clear();
        _AckTime.clear();
        _Send72Time.clear();
        _Recv72Time.clear();
        _Send73Time.clear();
        _Recv73Time.clear();
        _SendTreeTime.clear();
        _RecvTreeTime.clear();
        _FinTime.clear();
    }
}

//#############################################################################
void
CIFSTimer::printTimings(const Options & aOptions) const
{
    Timeval tmp;

    tmp = _AckTime - _StartTime;
    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|All|Time to first ACK\t"<<tmp.format()<<std::endl;


    long unsigned int a,b;
    a=_Recv72Time.tv_sec*1000000 + _Recv72Time.tv_usec;
    b=_Send72Time.tv_sec*1000000 + _Send72Time.tv_usec;
    
    if(a>b)
    {
        tmp = _Send72Time - _AckTime;
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|All|ACK to First Command Recv\t"
                 <<tmp.format()<<std::endl;

        tmp = _Recv72Time - _Send72Time;
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|All|Command Recv to First Command Send\t"
                 <<tmp.format()<<std::endl;

        tmp = _FinTime - _Recv72Time;
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|All|Command Recv to Connection End\t"
                 <<tmp.format()<<std::endl;
    }
    else
    {
        tmp = _Recv72Time - _AckTime;
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|All|ACK to First Command Recv\t"
                 <<tmp.format()<<std::endl;

        tmp = _Send72Time - _Recv72Time;
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|All|Command Recv to First Command Send\t"
                 <<tmp.format()<<std::endl;
        
        tmp = _FinTime - _Send72Time;
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|All|Command Recv to Connection End\t"
                 <<tmp.format()<<std::endl;
    }
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################

