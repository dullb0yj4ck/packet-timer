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
#include<pcapp/capture_descriptor.h>

// api includes

// tp includes
//#include<pcap.h>

// std includes
#include<cstdlib>
#include<cstring>

using namespace pcapp;

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

        try
        {
            // first get device
            NetworkDevice tNetworkingDevice();
            
            // then get network
            bpf_u_int32 tLocalSubnet;
            bpf_u_int32 tSubnetMask;
            tNetworkDevice.lookUpNetwork(tLocalSubnet, tSubnetMask);
            
            SharedCaptureDescriptorTS tCaptureDescriptor = 
                tNetworkingDevice.getCaptureDescriptor(BUFSIZ);
            
            tCaptureDescriptor->compileFilter("host www.google.com",
                                              tSubnetMask);
            
            std::string * tString = new std::string("Sample Argument");
            u_char * tPointer = (u_char *)tString;
            
            tCaptureDescriptor->runLoop(120, pcapCallback, tPointer);
            
        } 
        catch(const std::runtime_error & eProblem)
        {
            std::cout<<"Problem occurred: "
                     <<eProblem.what()<<std::endl;
        }
    }

 protected:

 private:

}; 

#endif
