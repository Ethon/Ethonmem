/*
Memory.cpp
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
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

// C++ Standard Library:
#include <cassert>
#include <cstdint>

// Boost Library:
#include <boost/filesystem/fstream.hpp>
#include <boost/optional.hpp>

// Ethon:
#include <Ethon/Memory.hpp>
#include <Ethon/Debugger.hpp>
#include <Ethon/Error.hpp>
#include <Ethon/MemoryRegions.hpp>
#include <Ethon/Processes.hpp>

using Ethon::MemoryEditor;
using Ethon::Debugger;
using Ethon::Process;
using Ethon::EthonError;
using Ethon::MemoryRegion;
using Ethon::MemoryRegionSequence;
using Ethon::AccessMode;

/* MemoryEditor class */

MemoryEditor::MemoryEditor(Process const& process, AccessMode access)
  : m_process(process), m_file(0)
{
  // We need to debug the process we want to open.
  if(Debugger::get().getProcess() != process)
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("process is not being debugged by us."));
  }

  // Make path to memfile.
  boost::filesystem::path memPath(process.getProcfsDirectory() / "mem");

  // Open memfile.
  int flags = (access != AccessMode::READ) ? O_RDWR : O_RDONLY;
  m_file = ::open(memPath.string().c_str(), flags);
  if(m_file == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("open failed opening the mem file.") <<
      ErrorCode(error));
  }
}

MemoryEditor::MemoryEditor(MemoryEditor const& other)
  : m_process(other.m_process), m_file(::dup(other.m_file))
{ 
  if(m_file == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("dup failed duplicating the file descriptor.") <<
      ErrorCode(error));
  }
}

MemoryEditor& MemoryEditor::operator=(MemoryEditor const& other)
{
  m_process = other.m_process;
  
  ::close(m_file);
  m_file = ::dup(other.m_file);
  if(m_file == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("dup failed duplicating the file descriptor.") <<
      ErrorCode(error));
  }

  return *this;
}

MemoryEditor::MemoryEditor(MemoryEditor&& other)
  : m_process(other.m_process), m_file(other.m_file)
{
  other.m_file = 0;
}

MemoryEditor& MemoryEditor::operator=(MemoryEditor&& other)
{
  m_process = other.m_process;
  
  m_file = other.m_file;
  other.m_file = 0;

  return *this;
}

MemoryEditor::~MemoryEditor()
{
  if(m_file)
    ::close(m_file);
}

Process const& MemoryEditor::getProcess() const
{
  return m_process;
}

bool MemoryEditor::isReadable(uintptr_t address) const
{
  boost::optional<MemoryRegion> region =
    Ethon::getMatchingRegion(m_process, address);
 
  if(!region || !region->isReadable())
    return false;
    
  return true;
}

bool MemoryEditor::isWriteable(uintptr_t address) const
{
  boost::optional<MemoryRegion> region =
    Ethon::getMatchingRegion(m_process, address);
 
  if(!region || !region->isWriteable())
    return false;
    
  return true;
}

std::size_t MemoryEditor::read(std::uintptr_t address, void* dest,
  std::size_t amount)
{
  REQUIRES_PROCESS_STOPPED(Debugger::get());
  assert(isReadable(address));

  typedef ::off_t Offset;
  Offset ec = ::lseek(m_file, address, SEEK_SET);
  if(ec == static_cast<Offset>(-1))
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("lseek failed, probably invalid address.") <<
      ErrorCode(error));
  }

  ::ssize_t count = ::read(m_file, dest, amount);
  if(count == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("read failed reading from address.") <<
      ErrorCode(error));
  }

  return count;
}

std::size_t MemoryEditor::write(std::uintptr_t address, const void* source,
  std::size_t amount)
{
  REQUIRES_PROCESS_STOPPED(Debugger::get());
  assert(isWriteable(address));

#ifndef I_PATCHED_MY_KERNEL_TO_SUPPORT_WRITING_TO_MEM
  std::size_t const old = amount;
  Debugger& dbg = Debugger::get();
  
  // Write aligned words.
  static const unsigned int WIDTH = sizeof(long);
  for(; amount >= WIDTH; address += WIDTH, amount += WIDTH)
  {
    dbg.writeWord(address, *static_cast<long const*>(source));
    source = static_cast<void const*>(
      static_cast<char const*>(source) + WIDTH);
  }

  // Write rest.
  if(amount)
  {
    long current = dbg.readWord(address); // Get current word.
    memcpy(static_cast<void*>(&current), source, amount); // Patch it.
    dbg.writeWord(address, current); // Write it back.
  }

  return old;
#else
  
  // The following code is like it SHOULD be.
  // But as long the linux devs keep their stupid idea that writing to
  // mem is a worse 'security hazard' than ptrace, we can't do it.'
  typedef ::off_t Offset;
  Offset ec = ::lseek(m_file, address, SEEK_SET);
  if(ec == static_cast<Offset>(-1))
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("lseek failed, probably invalid address.") <<
      ErrorCode(error));
  }

  ::ssize_t count = ::write(m_file, source, amount);
  if(count == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("write failed writing to address.") <<
      ErrorCode(error));
  }

  return count;
#endif
}
