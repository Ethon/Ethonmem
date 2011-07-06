/*
Scanner.cpp
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

// C++ Standard Library:
#include <cstdint>
#include <vector>
#include <algorithm>
#include <string>

// Boost Library:
#include <boost/foreach.hpp>

// Ethon:
#include <Ethon/Memory.hpp>
#include <Ethon/MemoryRegions.hpp>
#include <Ethon/Error.hpp>
#include <Ethon/Scanner.hpp>

using Ethon::MemoryEditor;
using Ethon::Scanner;
using Ethon::EthonError;
using Ethon::MemoryRegion;
using Ethon::MemoryRegionSequence;
using Ethon::ByteContainer;

struct WrappedByte
{
  WrappedByte(std::uint8_t value_, bool wildcard_)
    : value(value_), wildcard(wildcard_)
  { }

  std::uint8_t value;
  bool wildcard;
};

static std::vector<WrappedByte> compilePattern(std::string const& pattern,
  std::string const& mask)
{
  if(pattern.length() != mask.length())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      Ethon::ErrorString("Pattern and mask have not equal size"));
  }

  std::vector<WrappedByte> values;
  for(std::size_t i = 0, len = pattern.length(); i < len; ++i)
    values[i] = WrappedByte(pattern[i], mask[i] == '*');

  return std::move(values);
}

static bool operator==(std::uint8_t lhs, WrappedByte rhs)
{
  return rhs.wildcard ? true : lhs == rhs.value;
}

std::uintptr_t impl_findPattern(std::vector<WrappedByte> const& compiled,
  MemoryRegion const* region, MemoryEditor& edit)
{
  // If region is zero, scan all regions
  if(!region)
  {
    MemoryRegionSequence seq =
      makeMemoryRegionSequence(edit.getProcess());

    BOOST_FOREACH(MemoryRegion const& cur, seq)
    {
      std::uintptr_t result = impl_findPattern(compiled, &cur, edit);
      if(result)
        return result;
    }
  }

  // Else just scan the specified region
  else
  {
    ByteContainer buffer = edit.read<ByteContainer>(
      region->getStartAddress(), region->getSize());

    auto itr = std::search(buffer.begin(), buffer.end(),
      compiled.begin(), compiled.end());
    if(itr != buffer.end())
    {
      std::uintptr_t offset = itr - buffer.begin();
      return region->getStartAddress() + offset;
    }
  }

  return 0;
}


/* Scanner class */

Scanner::Scanner(MemoryEditor const& editor)
  : m_editor(editor)
{ }

std::uintptr_t Scanner::find(ByteContainer const& value,
  MemoryRegion const* region)
{
  // If region is zero, scan all regions
  if(!region)
  {
    MemoryRegionSequence seq =
      makeMemoryRegionSequence(m_editor.getProcess());

    BOOST_FOREACH(MemoryRegion const& cur, seq)
    {
      std::uintptr_t result = find(value, &cur);
      if(result)
        return result;
    }
  }

  // Else just scan the specified region
  else
  {
    ByteContainer buffer = m_editor.read<ByteContainer>(
    region->getStartAddress(), region->getSize());

    auto itr = std::search(buffer.begin(), buffer.end(),
      value.begin(), value.end());
    if(itr != buffer.end())
    {
      std::uintptr_t offset = itr - buffer.begin();
      return region->getStartAddress() + offset;
    }
  }

  return 0;
}

std::uintptr_t Scanner::find(ByteContainer const& value,
  std::string const& perms)
{
  if(perms.length() != 3)
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("No valid 'raw' permission string"));
  }

  bool mayRead    = perms[0] == 'r';
  bool mayWrite   = perms[1] == 'w';
  bool mayExecute = perms[2] == 'x';

  MemoryRegionSequence seq =
    makeMemoryRegionSequence(m_editor.getProcess());

  BOOST_FOREACH(MemoryRegion const& cur, seq)
  {
    if( (cur.isReadable() == mayRead || perms[0] == '*') &&
        (cur.isWriteable() == mayWrite || perms[1] == '*') &&
        (cur.isExecuteable() == mayExecute || perms[1] == '*') )
    {
      std::uintptr_t result = find(value, &cur);
      if(result)
        return result;
    }
  }

  return 0;
}
      
std::uintptr_t Scanner::findPattern(std::string const& pattern,
  std::string const& mask, MemoryRegion const* region)
{
  return impl_findPattern(compilePattern(pattern, mask), region, m_editor);
}

std::uintptr_t Scanner::findPattern(std::string const& pattern,
  std::string const& mask, std::string const& perms)
{
  if(perms.length() != 3)
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("No valid 'raw' permission string"));
  }

  auto compiled = compilePattern(pattern, mask);
  bool mayRead    = perms[0] == 'r';
  bool mayWrite   = perms[1] == 'w';
  bool mayExecute = perms[2] == 'x';

  MemoryRegionSequence seq =
    makeMemoryRegionSequence(m_editor.getProcess());
  BOOST_FOREACH(MemoryRegion const& cur, seq)
  {
    if( (cur.isReadable() == mayRead || perms[0] == '*') &&
        (cur.isWriteable() == mayWrite || perms[1] == '*') &&
        (cur.isExecuteable() == mayExecute || perms[1] == '*') )
    {
      std::uintptr_t result = impl_findPattern(compiled, &cur, m_editor);
      if(result)
        return result;
    }
  }

  return 0;
}
