/*
Debugger.cpp
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

// POSIX:
#include <sys/ptrace.h>
#include <sys/user.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

// C++ Standard Library:
#include <cerrno>
#include <cstdint>
#include <thread>
#include <functional>

// Boost Library:
#include <boost/foreach.hpp>
#include <boost/logic/tribool.hpp>

// Ethon:
#include <Ethon/Error.hpp>
#include <Ethon/Processes.hpp>
#include <Ethon/Debugger.hpp>

using Ethon::Debugger;
using Ethon::DebuggerRunner;
using Ethon::Process;
using Ethon::ProcessStatus;
using Ethon::EthonError;
using Ethon::Registers;
using Ethon::FpuRegisters;
using Ethon::SignalInfo;

/* Debugger class */

Debugger::Debugger(Process const& process)
  : m_process(process)
{ }

Debugger::~Debugger()
{
  try
  {
    detach();
  }
  catch(EthonError const&)
  { }
}

Process const& Debugger::getProcess() const
{
  return m_process;
}

void Debugger::attach() const
{
  long ec = ::ptrace(PTRACE_ATTACH, m_process.getPid(), 0, 0);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_ATTACH failed") <<
      ErrorCode(error));
  }
}

void Debugger::detach() const
{
  long ec = ::ptrace(PTRACE_DETACH, m_process.getPid(), 0, 0);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_DETACH failed") <<
      ErrorCode(error));
  }
}

void Debugger::continueExecution(int signalCode) const
{
  long ec = ::ptrace(PTRACE_CONT, m_process.getPid(), 0, signalCode);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_CONT failed") <<
      ErrorCode(error));
  }
}

void Debugger::singleStep(int signalCode) const
{
  long ec = ::ptrace(PTRACE_SINGLESTEP, m_process.getPid(), 0, signalCode);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_SINGLESTEP failed") <<
      ErrorCode(error));
  }
}

void Debugger::stepSyscall(int signalCode) const
{
  long ec = ::ptrace(PTRACE_SYSCALL, m_process.getPid(), 0, signalCode);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_SYSCALL failed") <<
      ErrorCode(error));
  }
}

void Debugger::kill() const
{
  long ec = ::ptrace(PTRACE_KILL, m_process.getPid(), 0, 0);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_KILL failed") <<
      ErrorCode(error));
  }
}

void Debugger::stop() const
{
  sendSignal(SIGSTOP);
}

void Debugger::cont() const
{
  sendSignal(SIGCONT);
}

void Debugger::sendSignal(int signalCode) const
{
  int ec = ::kill(m_process.getPid(), signalCode);
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("kill failed") <<
      ErrorCode(error));
  }
}

long Debugger::executeSyscall(
  unsigned long code, std::vector<unsigned long> const& args) const
{
  REQUIRES_PROCESS_STOPPED_INTERNAL();
  
  // Backup registers.
  Registers buRegs = getRegisters(buRegs);
  FpuRegisters buFregs = getFpuRegisters(buFregs);

  // Get register set to modify.
  Registers regs = buRegs;

  #if __WORDSIZE == 32

  // EAX stores the syscall code.
  regs.eax = code;

  // If less than 7 args exist, they are stored in registers.
  size_t argCount = args.size();
  if(argCount < 7)
  {
    while(argCount)
    {
      switch(argCount)
      {
      case 1:
        regs.ebx = args[0];
        break;

      case 2:
        regs.ecx = args[1];
        break;

      case 3:
        regs.edx = args[2];
        break;

      case 4:
        regs.esi = args[3];
        break;

      case 5:
        regs.edi = args[4];
        break;

      case 6:
        regs.ebp = args[5];
        break;
      }

      --argCount;
    }
  }

  // Otherwise we have to use memory.
  else
  {
    // Get stack space.
    regs.esp -= argCount * sizeof(unsigned long);

    // Write arguments to stack.
    for(size_t i = 0; i < argCount; ++i)
      writeWord(regs.esp + i * sizeof(unsigned long), args[i]);

    // EBX stores the address.
    regs.ebx = regs.esp;
  }

  // Write INT 0x80-instruction to current instruction pointer position.
  unsigned long const oldInstruction = readWord(regs.eip);

  uint8_t newInstruction[sizeof(long)] = { 0xCD, 0x80, 0xCC, 0xCC };
  writeWord(regs.eip, *reinterpret_cast<unsigned long*>(&newInstruction[0]));

  #elif __WORDSIZE == 64

  // RAX stores the syscall code.
  regs.rax = code;

  // If less than 7 args exist, they are stored in registers.
  size_t argCount = args.size();
  if(argCount < 7)
  {
    while(argCount)
    {
      switch(argCount)
      {
      case 1:
        regs.rdi = args[0];
        break;

      case 2:
        regs.rsi = args[1];
        break;

      case 3:
        regs.rdx = args[2];
        break;

      case 4:
        regs.r10 = args[3]; // Or RCX ???
        break;

      case 5:
        regs.r8 = args[4];
        break;

      case 6:
        regs.r9 = args[5];
        break;
      }

      --argCount;
    }
  }

  // Otherwise this fails.
  else
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("More than 6 arguments passed to a 64bit syscall"));
  }

  // Write SYSCALL-instruction to current instruction pointer position.
  unsigned long const oldInstruction = readWord(regs.rip);

  uint8_t newInstruction[sizeof(long)] =
    { 0x0F, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
  writeWord(regs.rip, *reinterpret_cast<unsigned long*>(&newInstruction[0]));
  #endif

  // Apply new registers.
  setRegisters(regs);

  // Step to begin of syscall.
  stepSyscall();

  // Step to end of syscall.
  stepSyscall();

  // Fetch return value and restore patched word
  getRegisters(regs);

  long returnValue;
  #if __WORDSIZE == 32
    returnValue = regs.eax;
    writeWord(regs.eip, oldInstruction);
  #elif __WORDSIZE == 64
    returnValue = regs.rax;
    writeWord(regs.rip, oldInstruction);
  #endif

  // Restore registers.
  setRegisters(buRegs);
  setFpuRegisters(buFregs);

  return returnValue;
}

unsigned long Debugger::readWord(uintptr_t address) const
{
  errno = 0;
  unsigned long result = ::ptrace(PTRACE_PEEKDATA, m_process.getPid(),
                          reinterpret_cast<void*>(address), 0);
  if(errno != 0)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_PEEKDATA failed") <<
      ErrorCode(error));
  }

  return result;
}

void Debugger::writeWord(uintptr_t address, unsigned long value) const
{
  void* temp = reinterpret_cast<void*>(address);
  long ec = ::ptrace(PTRACE_POKEDATA, m_process.getPid(), temp,
              reinterpret_cast<void*>(value));
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_POKEDATA failed") <<
      ErrorCode(error));
  }
}

unsigned long Debugger::readUserWord(uintptr_t offset) const
{
  errno = 0;
  unsigned long result = ::ptrace(PTRACE_PEEKUSER, m_process.getPid(),
                          reinterpret_cast<void*>(offset), 0);
  if(errno != 0)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_PEEKUSER failed") <<
      ErrorCode(error));
  }

  return result;
}

void Debugger::writeUserWord(uintptr_t offset, unsigned long value) const
{
  void* temp = reinterpret_cast<void*>(offset);
  long ec = ::ptrace(PTRACE_POKEUSER, m_process.getPid(), temp,
              reinterpret_cast<void*>(value));
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_POKEUSER failed") <<
      ErrorCode(error));
  }
}

Registers& Debugger::getRegisters(Registers& dest) const
{
    long ec = ::ptrace(PTRACE_GETREGS, m_process.getPid(), 0,
                static_cast<void*>(&dest));
    if(ec == -1)
    {
      std::error_code const error = Ethon::makeErrorCode();
      BOOST_THROW_EXCEPTION(EthonError() <<
        ErrorString("ptrace with PTRACE_GETREGS failed") <<
        ErrorCode(error));
    }

    return dest;
}

void Debugger::setRegisters(Registers const& registers) const
{
  long ec = ::ptrace(PTRACE_SETREGS, m_process.getPid(), 0,
              static_cast<const void*>(&registers));
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_SETREGS failed") <<
      ErrorCode(error));
  }
}

FpuRegisters& Debugger::getFpuRegisters(FpuRegisters& dest) const
{
    long ec = ::ptrace(PTRACE_GETFPREGS, m_process.getPid(), 0,
                static_cast<void*>(&dest));
    if(ec == -1)
    {
      std::error_code const error = Ethon::makeErrorCode();
      BOOST_THROW_EXCEPTION(EthonError() <<
        ErrorString("ptrace with PTRACE_GETFPREGS failed") <<
        ErrorCode(error));
    }

    return dest;
}

void Debugger::setFpuRegisters(FpuRegisters const& fpuRegisters) const
{
  long ec = ::ptrace(PTRACE_SETFPREGS, m_process.getPid(), 0,
              static_cast<const void*>(&fpuRegisters));
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_SETFPREGS failed") <<
      ErrorCode(error));
  }
}

SignalInfo& Debugger::getSignalInfo(SignalInfo& dest) const
{
    long ec = ::ptrace(PTRACE_GETSIGINFO, m_process.getPid(), 0,
                static_cast<void*>(&dest));
    if(ec == -1)
    {
      std::error_code const error = Ethon::makeErrorCode();
      BOOST_THROW_EXCEPTION(EthonError() <<
        ErrorString("ptrace with PTRACE_GETSIGINFO failed") <<
        ErrorCode(error));
    }

    return dest;
}

void Debugger::setSignalInfo(SignalInfo const& signalInfo) const
{
  long ec = ::ptrace(PTRACE_SETSIGINFO, m_process.getPid(), 0,
              static_cast<const void*>(&signalInfo));
  if(ec == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("ptrace with PTRACE_SETSIGINFO failed") <<
      ErrorCode(error));
  }
}

/* DebuggerRunner class */

DebuggerRunner::DebuggerRunner(Debugger const& debugger)
  : m_debugger(debugger), m_worker(), m_callback(defaultCallback),
    m_stopped(boost::indeterminate)
 { }

DebuggerRunner::~DebuggerRunner()
{
  stop();
}

void DebuggerRunner::run()
{
  m_stopped = false;
  m_worker = std::thread(&DebuggerRunner::work, this);
}

void DebuggerRunner::stop()
{
  m_stopped = true;
  m_worker.detach();
}

Debugger const& DebuggerRunner::getDebugger() const
{
  return m_debugger;
}

boost::tribool DebuggerRunner::wasStopped() const
{
  return m_stopped;
}

void DebuggerRunner::setCallback(SignalCallback const& callback)
{
  m_callback = callback;
}

void DebuggerRunner::work()
{
  for(;;)
  {
    int status;
    ::pid_t result = ::waitpid(m_debugger.getProcess().getPid(), &status, 0);
    if(result == -1)
    {
      m_stopped = boost::indeterminate;
      break;
    }

    // If process terminated, stop
    if(WIFEXITED(status) || WIFSIGNALED(status))
    {
      m_stopped = boost::indeterminate;
      break;
    }

    // If process was stopped by a signal, call callback
    if(WIFSTOPPED(status))
    {
      int signal = WSTOPSIG(status);
      if(!m_callback(m_debugger, signal))
        break;
    }
  }
}

bool DebuggerRunner::defaultCallback(Debugger const& debugger, int signalCode)
{
  if(signalCode != SIGTRAP)
    debugger.continueExecution();

  return true;
}
