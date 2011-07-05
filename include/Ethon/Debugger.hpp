/*
Debugger.hpp
This File is a part of Ethonmem, a memory hacking library for linux
Copyright (C) < 2011, Ethon >
              < ethon@ethon.cc - http://ethon.cc >

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef __ETHON_DEBUGGER_HPP__
#define __ETHON_DEBUGGER_HPP__

// POSIX:
#include <sys/user.h>
#include <signal.h>

// C++ Standard Library:
#include <cstdint>
#include <thread>
#include <functional>
#include <vector>
#include <utility>

// Boost Library:
#include <boost/logic/tribool.hpp>
#include <boost/noncopyable.hpp>

// Ethon:
#include <Ethon/Processes.hpp>

/* Macros for use in Debugger::readUserWord / Debugger::writeUserWord() */
#define GET_FIELDOFFSET(structure, name) \
  reinterpret_cast<uintptr_t>(&reinterpret_cast<##structure##*>(0)->name);

#define GET_FIELDOFFSET_EX(structure, substructure, name) \
  reinterpret_cast<uintptr_t>(&reinterpret_cast<##structure##*>(0) \
  ->##substructure##.name);

namespace Ethon
{
  typedef ::user_regs_struct    Registers;
  typedef ::user_fpregs_struct  FpuRegisters;
  typedef ::siginfo_t           SignalInfo;

  /**
  * Class offering utilities to debug an application.
  * Requires root permissions.
  */
  class Debugger
  {
  private:
    Process m_process;

  public:

    /**
    * Constructor gathering required data for debugging from a process object.
    * @param process A process object.
    */
    Debugger(Process const& process);

    /**
    * Destructor calling detach exception-save.
    */
    ~Debugger();

    /**
    * Return the debugged process.
    * @return The debugged process.
    */
    Process const& getProcess() const;

    /**
    * Attaches to the process set before, making it a traced "child" of the
    * calling process; The  calling  process actually becomes the parent of
    * the child process for most purposes (e.g., it will receive notification
    * of child events and appears in ps(1) output as the child's parent), but
    * a getppid(2) by the child will still return the PID of the original
    * parent. The child is sent a SIGSTOP, but will not necessarily have
    * stopped by the completion of this call.
    */
    void attach() const;

    /**
    * Restarts the stopped debugged process and detaches from the process.
    */
    void detach() const;

    /**
    * Restarts the stopped debugged process.
    * @param signalCode If not zero, this will be sent as signal code.
    * No signal is sent otherwise.
    */
    void continueExecution(int signalCode = 0) const;

    /**
    * Restarts the stopped debugged process, but arranges for the debugged
    * process to be stopped after execution of a single instruction.
    * @param signalCode If not zero, this will be sent as signal code.
    * No signal is sent otherwise.
    */
    void singleStep(int signalCode = 0) const;

    /**
    * Restarts the stopped debugged process, but arranges for the debugged
    * process to be stopped at the next entry to or exit from a  system  call.
    * @param signalCode If not zero, this will be sent as signal code.
    * No signal is sent otherwise.
    */
    void stepSyscall(int signalCode = 0) const;

    /**
    * Sends the debugged process a SIGKILL to terminate it.
    */
    void kill() const;

    /**
    * Sends the debugged process a SIGSTOP to stop it.
    */
    void stop() const;
    
    /**
    * Sends the debugged process a SIGCONt to continue it.
    */
    void cont() const;

    /**
    * This can be used to send any signal to the debugged process.
    * @param signalCode The signal to send.
    */
    void sendSignal(int signalCode) const;

    /**
    * Reads a word from the debugged process's memoryspace.
    * @param address The address to read from.
    * @return The read word.
    */
    unsigned long readWord(uintptr_t address) const;

    /**
    * Writes a word to the debugged process's memoryspace.
    * @param address The address to write to.
    * @param value The word to write.
    */
    void writeWord(uintptr_t address, unsigned long value) const;

    /**
    * Reads a word from the debugged process's user area.
    * Use <sys/user.h> and GET_FIELDOFFSET/GET_FIELDOFFSETEX to determine
    * offsets.
    * @param offset The offset to read from.
    * @return The read word.
    */
    unsigned long readUserWord(uintptr_t offset) const;

    /**
    * Writes a word to the debugged process's user area.
    * Use <sys/user.h> and GET_FIELDOFFSET/GET_FIELDOFFSETEX to determine
    * offsets.
    * @param offset The offset to write to.
    * @param value The word to write.
    */
    void writeUserWord(uintptr_t offset, unsigned long value) const;

    /**
    * Copies the debugged process's general purpose registers.
    * See <sys/user.h> for further information.
    * @param dest Structure to hold the copied registers.
    * @return Same as dest.
    */
    Registers& getRegisters(Registers& dest) const;

    /**
    * Overwrites the debugged process's general purpose registers.
    * See <sys/user.h> for further information.
    * @param registers Structure holding the registers to write.
    */
    void setRegisters(Registers const& registers) const;

    /**
    * Copies the debugged process's floating-point registers.
    * See <sys/user.h> for further information.
    * @param dest Structure to hold the copied registers.
    * @return Same as dest.
    */
    FpuRegisters& getFpuRegisters(FpuRegisters& dest) const;

    /**
    * Overwrites the debugged process's floating-point registers.
    * See <sys/user.h> for further information.
    * @param fpuRegisters Structure holding the registers to write.
    */
    void setFpuRegisters(FpuRegisters const& fpuRegisters) const;

    /**
    * Retrieves information about the signal that caused the stop.
    * @param dest Structure to hold the siginfo.
    * @return Same as dest.
    */
    SignalInfo& getSignalInfo(SignalInfo& dest) const;

    /**
    * Overwrites signal information.
    * @param signalInfo The siginfo to write.
    */
    void setSignalInfo(SignalInfo const& signalInfo) const;
  };

  /* RAII-class which cares about stopping a process */
  struct RequireProcessStopped : private boost::noncopyable
  {
    Debugger const& m_debugger;
    bool m_stopped;
        
    inline RequireProcessStopped(Debugger const& debugger)
      : m_debugger(debugger)
    {
      ProcessStatus status;
      debugger.getProcess().getStatus(status);
      m_stopped = status.isStopped();
          
      if(!m_stopped)
        debugger.stop();
    }
        
    inline ~RequireProcessStopped()
    {
      if(!m_stopped)
        m_debugger.cont();
    }
  };
}

#define REQUIRES_PROCESS_STOPPED(debugger) \
  Ethon::RequireProcessStopped req_proc_stppd__##__LINE__ (debugger);
  
#define REQUIRES_PROCESS_STOPPED_INTERNAL() \
  REQUIRES_PROCESS_STOPPED(*this)

#endif // __ETHON_DEBUGGER_HPP__
