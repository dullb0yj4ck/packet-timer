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
 * Author: Michael Linck
 */


#ifndef PCAP_TEST_H
#define PCAP_TEST_H

// our includes

// api includes

// tp includes
#include<pcap.h>

// std includes
#include<cstdlib>
#include<cstring>

//using namespace mon;

//#############################################################################
class Test : public CxxTest::TestSuite
{
 public:
    static void pcapCallback(u_char *aArguments,
                             const pcap_pkthdr * aPacketHeader,
                             const u_char * aPacket)
    {
        std::string * tArgs = (std::string *)(aArguments);
        
        std::cout<<"pcapCallback called with: "<<*tArgs<<std::endl;
    }

    
    //#########################################################################
    void testPCAP()
    {
        std::cout<<std::endl<<std::endl;
        std::cout<<"Testing PCAP"<<std::endl<<std::endl;

        // set up pcap
        char tErrorBuffer[PCAP_ERRBUF_SIZE];
        
        // first get device
        tErrorBuffer[0] = 0;
        char * tNetworkingDevice = pcap_lookupdev(tErrorBuffer);
        if(tNetworkingDevice != NULL)
        {
            std::cout<<"pcap found networking device: "
                     <<tNetworkingDevice<<std::endl;
            if(strlen(tErrorBuffer) == 0)
            {
                std::cout<<"without warnings"<<std::endl;
            }
            else
            {
                std::cout<<"with warning: "<<tErrorBuffer<<std::endl;
            }
            // then get network
            bpf_u_int32 tLocalSubnet;
            bpf_u_int32 tSubnetMask;
            tErrorBuffer[0] = 0;
            int tLookupResult = pcap_lookupnet(tNetworkingDevice,
                                               &tLocalSubnet,
                                               &tSubnetMask,
                                               tErrorBuffer);
            
            if(tLookupResult >= 0)
            {
                std::cout<<"pcap network lookup successfull"<<std::endl;
                std::cout<<"Local Subnet: "<<tLocalSubnet<<std::endl;
                std::cout<<"Local Subnet Mask: "<<tSubnetMask<<std::endl;

                if(strlen(tErrorBuffer) == 0)
                {
                    std::cout<<"without warnings"<<std::endl;
                }
                else
                {
                    std::cout<<"with warning: "<<tErrorBuffer<<std::endl;
                }
                tErrorBuffer[0] = 0;
                
                pcap_t * tPacketCaptureDescriptor = 
                    pcap_open_live(tNetworkingDevice,
                                   BUFSIZ,
                                   1,
                                   2000, 
                                   tErrorBuffer);
                if(tPacketCaptureDescriptor != NULL)
                {
                    std::cout<<"pcap opened capture descriptor ";
                    if(strlen(tErrorBuffer) == 0)
                    {
                        std::cout<<"without warnings"<<std::endl;
                    }
                    else
                    {
                        std::cout<<"with warning: "<<tErrorBuffer<<std::endl;
                    }


                    bpf_program tFilterCode;
                    
                    
                    if(pcap_compile(tPacketCaptureDescriptor,
                                    &tFilterCode,
                                    "host www.google.com",
                                    0,
                                    tSubnetMask) != -1)
                    {
                        std::cout<<"pcap compiled filter"<<std::endl;
                        
                        if(pcap_setfilter(tPacketCaptureDescriptor,
                                          &tFilterCode) != -1)
                        {
                            std::cout<<"pcap filter set"<<std::endl;
                            std::string * tString =
                                new std::string("Sample Argument");
                            
                            pcap_loop(tPacketCaptureDescriptor,
                                      120,
                                      pcapCallback,
                                      (u_char *)tString);
                        } 
                        else
                        {
                            std::cout<<"Couldn't set pcap filter: "
                                     <<pcap_geterr(tPacketCaptureDescriptor)
                                     <<std::endl;
                        }
                    }
                    else
                    {
                        std::cout<<"Couldn't compile filter expression"
                                 <<pcap_geterr(tPacketCaptureDescriptor)
                                 <<std::endl;
                    }
                }
                else
                {
                    std::cout<<"pcap failed to open capture descriptor: "
                             <<tErrorBuffer<<std::endl;
                }
            }
            else
            {
                std::cout<<"pcap network lookup failed with error: "
                         <<tErrorBuffer<<std::endl;
            }
        }
        else
        {
            std::cout<<"pcap coudln't find device.  Error: "
                     <<tErrorBuffer<<std::endl;
        }
        


        // remember to free networking device
        // .. somehow, but apparently not like this
        //free(tNetworkingDevice);
    }

 protected:

 private:

}; 

#endif
