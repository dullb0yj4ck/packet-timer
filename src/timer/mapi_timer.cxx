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
#include<pcapp/timer/mapi_timer.h>

// api includes

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
MAPITimer::MAPITimer(const std::string & aLabel)
    :
    _Label(aLabel),
    _StartTime(),
    _AckTime(),
    _EndTime(),
    _DCE1RequestTime(),
    _DCE1ResponseTime(),
    _NewDCEChainTime(),
    _DCEChainCloseTime(),
    _ChainCount(0),
    _ChainDuration(0)
{
}

//#############################################################################
void 
MAPITimer::handleData(Options *opts,
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
    //long unsigned int begin,end;

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
    

    if(!_StartTime.isSet())
    {
        if(!incoming && size_payload == 0 && tcph->syn && (! tcph->ack))
        {
            _Label = "Exchange\0";
            _StartTime = ts;
        }
    }
    else if(!_AckTime.isSet())
    {
        if(!incoming && size_payload == 0 && tcph->ack && (! tcph->syn))
        {
            _AckTime = ts;
        }
    }
    else if(!_DCE1RequestTime.isSet())
    {
        if(size_payload > 0 && 
           payload[0] == 0x05 && 
           payload[1] == 0x00 &&
           payload[48] == 0x01)
        {
            _ChainCount++;
            _NewDCEChainTime = ts;
            _DCE1RequestTime = ts;
        }
    }
    else if(!_DCE1ResponseTime.isSet())
    {
        if(size_payload > 0 &&
           payload[0] == 0x05 &&
           payload[1] == 0x00 &&
           payload[48] == 0x01)
        {
            _ChainCount++;
            _NewDCEChainTime = ts;
            _DCE1ResponseTime = ts;
        }
    }
    else if((!incoming) && 
            (size_payload == 0) && 
            (tcph->fin) &&
            (ntohs(tcph->source) != 135) &&
            (ntohs(tcph->source) != 135 ))
    {
        /*begin=cur_mapi_timer->newdcechain.tv_sec*1000000 + cur_mapi_timer->newdcechain.tv_usec;*/
        /*end = (ts.tv_sec*1000000+ts.tv_usec) - begin;*/
        /*(cur_mapi_timer->chain_duration) += end;*/
        printTimings(*opts);

        _Label = "";
        _StartTime.clear();
        _AckTime.clear();
        _EndTime.clear();
        _DCE1RequestTime.clear();
        _DCE1ResponseTime.clear();
        _NewDCEChainTime.clear();
        _DCEChainCloseTime.clear();
        
        _ChainCount = 0;
        _ChainDuration = 0;

    }
}

//#############################################################################
void
MAPITimer::printTimings(const Options & aOptions) const
{
    Timeval tmp;
    
    tmp = _AckTime - _StartTime;
    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|"<<_Label
             <<"|Time to First ACK\t"<<tmp.format()<<std::endl;


    
    tmp = _DCE1RequestTime - _AckTime;
    if(tmp.tv_sec > 0)
    {
        std::cout<<"Net|Protocol|"<<aOptions.protocol
                 <<"|Time|"<<_Label
                 <<"|Time to First RPC Request\t"<<tmp.format()<<std::endl;
    }
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################

