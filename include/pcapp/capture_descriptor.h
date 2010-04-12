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

#ifndef _pcapp_capture_descriptor_h
#define _pcapp_capture_descriptor_h

// api includes

// tp includes
#include<pcap.h>
#include<boost/noncopyable.hpp>
#include<boost/shared_ptr.hpp>

// std includes
#include<string>
//#include<vector>

namespace pcapp
{
    class NetworkDevice;

    //#########################################################################
    /**
     * A wrapper for the pcap_t type.  To simplify program flow, the 
     * boolean function return values are checked internally and turned
     * into exceptions upon failure.
     * @author mgl
     */
    //#########################################################################
    class CaptureDescriptor : boost::noncopyable
    {
    public:

        //#####################################################################
        /**
         * Compiles the pcap expression into a filter
         * @author mgl
         */
        //#####################################################################
        void compileFilter(const std::string & aExpression,
                           bpf_u_int32 aSubnetMask = 0,
                           bool aOptimized = false);
                
        //#####################################################################
        /**
         * Runs the pcap loop
         * @author mgl
         */
        //#####################################################################
        void runLoop(int aNumberOfTimes,
                     pcap_handler aCallback,
                     u_char *aDataToHandToCallback);

        //#####################################################################
        /**
         * @author mgl
         */
        //#####################################################################
        virtual ~CaptureDescriptor();
    protected:
            
    private:
        friend class NetworkDevice;

        /// filter code
        bpf_program _FilterCode;
        /// pcap descriptor
        pcap_t * _PCAPDescriptor;

        //#####################################################################
        /**
         * Constructs the Descriptor using the pcap interface or throws
         * an exception if a problem is encountered.
         * @author mgl
         */
        //#####################################################################
        CaptureDescriptor(const std::string & aNetworkingDevice,
                          int aBufferSize,
                          bool aPromiscuous = true,
                          int aReadTimeoutInMilliseconds = 2000,
                          bool aSuperCareful = false);


        //#####################################################################
        /**
         * sets the pcap filter
         * @author mgl
         */
        //#####################################################################
        void setFilter();
    };

    typedef boost::shared_ptr<CaptureDescriptor> SharedCaptureDescriptorTS;

}

#endif
