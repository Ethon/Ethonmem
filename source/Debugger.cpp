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

// Ethon:
#include <Ethon/Error.hpp>
#include <Ethon/Processes.hpp>
#include <Ethon/Debugger.hpp>

using Ethon::Debugger;
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
  
  // Wait for process to stop.
  int status;
  if(waitpid(m_process.getPid(), &status, 0) == -1 || !WIFSTOPPED(status))
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("wait failed") <<
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