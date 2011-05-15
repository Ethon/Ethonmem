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

MemoryEditor::MemoryEditor(Debugger const& debugger, AccessMode access)
  : m_debugger(debugger), m_file(0)
{
  boost::filesystem::path memPath(
    debugger.getProcess().getProcfsDirectory() / "mem");
  if(!boost::filesystem::exists(memPath))
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Error finding mem file."));
  }
  
  bool write = (access != AccessMode::READ);
  int flags = write ? O_RDWR : O_RDONLY;
  
  int fd = ::open(memPath.string().c_str(), flags);
  if(fd == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("open failed opening the mem file.") <<
      ErrorCode(error));
  }
  
  m_file = fd;
}

MemoryEditor::MemoryEditor(MemoryEditor const& other)
  : m_debugger(other.m_debugger), m_file(0)
{
  int fd = ::dup(other.m_file);
  if(fd == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("dup failed duplicating the file descriptor.") <<
      ErrorCode(error));
  }
  
  m_file = fd;
}

MemoryEditor& MemoryEditor::operator=(MemoryEditor const& other)
{
  this->m_debugger = other.m_debugger;
  
  ::close(m_file);
  int fd = ::dup(other.m_file);
  if(fd == -1)
  {
    std::error_code const error = Ethon::makeErrorCode();
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("dup failed duplicating the file descriptor.") <<
      ErrorCode(error));
  }
  
  m_file = fd;
  return *this;
}

MemoryEditor::~MemoryEditor()
{
  ::close(m_file);
}

Process const& MemoryEditor::getProcess() const
{
  return m_debugger.getProcess();
}

Debugger const& MemoryEditor::getDebugger() const
{
  return m_debugger;
}

bool MemoryEditor::isReadable(uintptr_t address) const
{
  boost::optional<MemoryRegion> reg =
    Ethon::getMatchingRegion(m_debugger.getProcess(), address);
 
  if(!reg || !reg->isReadable())
    return false;
    
  return true;
}

bool MemoryEditor::isWriteable(uintptr_t address) const
{
  boost::optional<MemoryRegion> reg =
    Ethon::getMatchingRegion(m_debugger.getProcess(), address);
 
  if(!reg || !reg->isWriteable())
    return false;
    
  return true;
}

size_t MemoryEditor::read(
        uintptr_t address, void* dest, size_t amount)
{
  REQUIRES_PROCESS_STOPPED(m_debugger);
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

size_t MemoryEditor::write(
        uintptr_t address, const void* source, size_t amount)
{
  REQUIRES_PROCESS_STOPPED(m_debugger);
  assert(isWriteable(address));

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
}
