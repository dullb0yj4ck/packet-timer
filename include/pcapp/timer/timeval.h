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

#ifndef _pcapp_timer_timeval_h
#define _pcapp_timer_timeval_h

// api includes
//#include<pcapp/capture_descriptor.h>

// tp includes
//#include<pcap.h>
#include <sys/time.h>

// std includes
#include<string>


namespace pcapp
{
    namespace timer
    {
        //#####################################################################
        /**
         * A wrapper for the pcap network device string.
         * Boolean function return values are checked internally and turned
         * into exceptions upon failure for simpler user-code.
         * @author mgl
         */
        //#####################################################################
        class Timeval : public timeval
        {
        public:
            //#################################################################
            /**
             * @author mgl
             */
            //#################################################################
            Timeval();

            //#################################################################
            /**
             * @author mgl
             */
            //#################################################################
            Timeval(const timeval & aTimeval);
 
            //#################################################################
            /**
             * @author mgl
             */
            //#################################################################
            void clear();

            //#################################################################
            /**
             * @author mgl
             */
            //#################################################################
            std::string format();

            //#################################################################
            /**
             * @author mgl
             */
            //#################################################################
            bool isSet();

            //#################################################################
            /**
             * @author mgl
             */
            //#################################################################
            Timeval operator-(const Timeval & aTime) const;

        protected:
            
        private:
        };
    }
}

#endif
