/*
Scanner.hpp
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

#ifndef __ETHON_SCANNER_HPP__
#define __ETHON_SCANNER_HPP__

// C++ Standard Library:
#include <cstdint>
#include <vector>
#include <string>

// Ethon:
#include <Ethon/Memory.hpp>
#include <Ethon/MemoryRegions.hpp>

namespace Ethon
{
  typedef std::vector<uint8_t> ByteContainer;

  /**
  * Converts a POD value into a byte-representation.
  * @param value Value to convert.
  * @result The converted value.
  */
  template<class T>
  ByteContainer getBytes(T const& value,
    typename std::enable_if<std::is_pod<T>::value,T>::type* /*dummy*/ = 0)
  {
    ByteContainer temp(sizeof(T));
    *reinterpret_cast<T*>(&temp[0]) = value;
    return temp;
  }

  /**
  * Converts a string value into a byte-representation.
  * @param value Value to convert.
  * @result The converted value.
  */
  template <typename T>
  ByteContainer getBytes(std::basic_string<T> const& value)
  {
    ByteContainer temp(value.length() * sizeof(T));
    value.copy(reinterpret_cast<T*>(&temp[0]), value.length());
    return temp;
  }

  /**
  * Converts a vector of POD values into a byte-representation.
  * @param value Vector of values to convert.
  * @result The converted values.
  */
  template <typename T>
  ByteContainer getBytes(std::vector<T> const& value)
  {
    static_assert(std::is_pod<T>::value,
      "getBytes() Error : Vector of POD values required");

    ByteContainer temp(value.size() * sizeof(T));
    std::copy(&value[0], &value[value.size()], reinterpret_cast<T*>(&temp[0]));
    return temp;
  }

  /**
  * Scans a process' memory for values.
  */
  class Scanner
  {
  private:
    MemoryEditor m_editor;

  public:
    /**
    * Constructor initializing the scanner object.
    * @param editor MemoryEditor the Scanner may use for reading memory. 
    */
    Scanner(MemoryEditor const& editor);

    /**
    * Finds a value inside a memory region.
    * @param value Value to find.
    * @param region The memory region which should be searched.
    * If NULL, all regions will be searched.
    * @result An address or 0 if the value could not be found. 
    */
    uintptr_t find(ByteContainer const& value,
      MemoryRegion const* region = 0);

    /**
    * Finds a value inside memory matching a permission pattern.
    * @param value Value to find.
    * @param perms A string consisting of 3 chars, [rwx], where a '-' means
    * that the operation should NOT be allowed and '*' means that you want to
    * ignore that operation. For instance, "r-*" searches all memory which is
    * readable, non-writeable, executeable OR non-executeable. 
    * @result An address or 0 if the value could not be found. 
    */
    uintptr_t find(ByteContainer const& value,
      std::string const& perms);

    /**
    * Finds a POD value inside a memory region.
    * @param value Value to find.
    * @param region The memory region which should be searched.
    * If NULL, all regions will be searched.
    * @result An address or 0 if the value could not be found. 
    */
    template<typename T>
    uintptr_t find(T const& value, MemoryRegion const* region = 0,
      typename std::enable_if<std::is_pod<T>::value,T>::type* /*dummy*/ = 0)
    {
      return find(getBytes(value), region);
    }

    /**
    * Finds a POD value inside memory matching a permission pattern.
    * @param value Value to find.
    * @param perms A string consisting of 3 chars, [rwx], where a '-' means
    * that the operation should NOT be allowed and '*' means that you want to
    * ignore that operation. For instance, "r-*" searches all memory which is
    * readable, non-writeable, executeable OR non-executeable. 
    * @result An address or 0 if the value could not be found. 
    */
    template<typename T>
    uintptr_t find(T const& value, std::string const& perms,
      typename std::enable_if<std::is_pod<T>::value,T>::type* /*dummy*/ = 0)
    {
      return find(getBytes(value), perms);
    }

    /**
    * Finds a string inside a memory region.
    * @param value String to find.
    * @param region The memory region which should be searched.
    * If NULL, all regions will be searched.
    * @result An address or 0 if the value could not be found. 
    */
    template <typename T>
    uintptr_t find(std::basic_string<T> const& value,
      MemoryRegion const* region = 0)
    {
      return find(getBytes(value), region);
    }

    /**
    * Finds a string inside memory matching a permission pattern.
    * @param value String to find.
    * @param perms A string consisting of 3 chars, [rwx], where a '-' means
    * that the operation should NOT be allowed and '*' means that you want to
    * ignore that operation. For instance, "r-*" searches all memory which is
    * readable, non-writeable, executeable OR non-executeable. 
    * @result An address or 0 if the value could not be found. 
    */
    template <typename T>
    uintptr_t find(std::basic_string<T> const& value,
      std::string const& perms)
    {
      return find(getBytes(value), perms);
    }

    /**
    * Finds a vector of POD values inside a memory region.
    * @param value Vector to find.
    * @param region The memory region which should be searched.
    * If NULL, all regions will be searched.
    * @result An address or 0 if the value could not be found. 
    */
    template <typename T>
    uintptr_t find(std::vector<T> const& value,
      MemoryRegion const* region = 0)
    {
      return find(getBytes(value), region);
    }
 
    /**
    * Finds a vector of POD values inside memory matching a permission pattern.
    * @param value Vector to find.
    * @param perms A string consisting of 3 chars, [rwx], where a '-' means
    * that the operation should NOT be allowed and '*' means that you want to
    * ignore that operation. For instance, "r-*" searches all memory which is
    * readable, non-writeable, executeable OR non-executeable. 
    * @result An address or 0 if the value could not be found. 
    */
    template <typename T>
    uintptr_t find(std::vector<T> const& value,
      std::string const& perms)
    {
      return find(getBytes(value), perms);
    }
  };
}

#endif // __ETHON_SCANNER_HPP__
