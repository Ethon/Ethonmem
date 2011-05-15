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

/* Scanner class */

Scanner::Scanner(MemoryEditor const& editor)
  : m_editor(editor)
{ }

uintptr_t Scanner::find(ByteContainer const& value,
  MemoryRegion const* region)
{
  // If region is zero, scan all regions
  if(!region)
  {
    MemoryRegionSequence seq =
      makeMemoryRegionSequence(m_editor.getProcess());

    BOOST_FOREACH(MemoryRegion const& cur, seq)
    {
      uintptr_t result = find(value, &cur);
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
      uintptr_t offset = itr - buffer.begin();
      return region->getStartAddress() + offset;
    }
  }

  return 0;
}

uintptr_t Scanner::find(ByteContainer const& value, std::string const& perms)
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
      uintptr_t result = find(value, &cur);
      if(result)
        return result;
    }
  }

  return 0;
}
