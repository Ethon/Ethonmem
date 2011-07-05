/*
MemoryRegions.hpp
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

#ifndef __ETHON_MEMORYREGIONS_HPP__
#define __ETHON_MEMORYREGIONS_HPP__

// C++ Standard Library:
#include <string>
#include <array>
#include <cstdint>
#include <algorithm>
#include <utility>
#include <cstdio>

// Boost Library:
#include <boost/iterator/iterator_facade.hpp>
#include <boost/optional.hpp>

// Ethon:
#include <Ethon/Processes.hpp>

namespace Ethon
{
  /**
  * The currently mapped memory regions and their access permissions.
  */
  class MemoryRegion
  {
    friend class MemoryRegionIterator;

  private:

    enum Perms
    {
      kPerm_Read,
      kPerm_Write,
      kPerm_Execute,
      kPerm_Shared
    };

    std::uintptr_t   	  m_start;    // Begin of the address space.
    std::uintptr_t   	  m_end;      // End of the address space.
    std::array<char, 4> m_perms;    // A set of permissions.
    std::uint32_t   	  m_offset;   // The offset into the file.
    std::uint16_t    	  m_devMajor; // The major device number.
    std::uint16_t    	  m_devMinor; // The minor device numer.
    std::uint32_t       m_inode;    // The inode on that device.
    std::string         m_path;     // The path of the mapped file.

  public:

    /**
    * Default constructor creating an unassociated memory region object.
    */
    MemoryRegion();

    /**
    * Gets the memory region's virtual start address.
    * @return The memory region's virtual start address.
    */
    std::uintptr_t getStartAddress() const;

    /**
    * Gets the memory region's virtual end address.
    * @return The memory region's virtual end address.
    */
    std::uintptr_t getEndAddress() const;

    /**
    * Gets the memory region's size.
    * @return The memory region's size.
    */
    std::size_t getSize() const;

    /**
    * Checks if reading from the memory region is allowed.
    * @return True if readable, false otherwise.
    */
    bool isReadable() const;

    /**
    * Checks if writing to the memory region is allowed.
    * @return True if writeable, false otherwise.
    */
    bool isWriteable() const;

    /**
    * Checks if the memory region is executeable.
    * @return True if executeable, false otherwise.
    */
    bool isExecuteable() const;

    /**
    * Checks if the memory regions is shared.
    * @return True if shared, false otherwise.
    */
    bool isShared() const;

    /**
    * Checks if the memory region is private.
    * @return True if private, false otherwise.
    */
    bool isPrivate() const;

    /**
    * Returns the memory region's permissions in a format rwx plus a fourth
    * byte which is either 'p' or 's', indicating if the region is shared.
    * @return The memory regions permissions.
    */
    const std::array<char, 4>& getPermissions() const;

    /**
    * Gets the offset into the mapped file.
    * @return The offset into the mapped file.
    */
    std::uint32_t getOffset() const;

    /**
    * Gets the major device number of the device containing the mapped file.
    * @return The major device number.
    */
    std::uint16_t getDeviceMajor() const;

    /**
    * Gets the minor device number of the device containing the mapped file.
    * @return The minor device number.
    */
    std::uint16_t getDeviceMinor() const;

    /**
    * Gets the inode on the device of the mapped file.
    * @return The inode on the device.
    */
    std::uint32_t getInode() const;

    /**
    * Retrieves the full path of the mapped file.
    * Some regions which are not associated to a file leave this field blank.
    * Other unassociated regions, like [heap], fill this reagion 
    * @return The path of the mapped file.
    */
    const std::string& getPath() const;
  };

  /**
  * Iterates over all memory regions of a process.
  * This iterator only creates flat copies when copied, so handle a copy like
  * a reference and don't attempt to use copies among multibly threads.
  * So, whenever possible, use move-semantics instead.
  */
  class MemoryRegionIterator
    : public boost::iterator_facade<  MemoryRegionIterator,
                                      MemoryRegion,
                                      boost::forward_traversal_tag >
  {
  private:

    friend class boost::iterator_core_access;

    /**
     * Parses a line from /proc/[pid]/maps and stores it.
     * @param line Line to parse.
     * @return Number of read fields.
     */
    int parse(char const* line);

    /**
    * Increments the iterator to point to the next entry.
    */
    void increment();

    /**
    * Checks if both iterators have the same validity-state.
    * @param other An other iterator to check equality with.
    * @return True if both have the same validity-state, false otherwise.
    */
    bool equal(MemoryRegionIterator const& other) const;

    /**
    * Returns a reference to the current entry.
    * @return A reference to the current entry.
    */
    MemoryRegion& dereference() const;

    mutable MemoryRegion m_current;
    FILE* m_maps;

  public:

    /**
    * Default constructor creating an invalid iterator.
    */
    MemoryRegionIterator();

    /**
    * Constructor creating an iterator for iterating a process memory regions.
    * @param process A process object specifying a process.
    */
    explicit MemoryRegionIterator(Process const& process);

    /**
    * Move-Constructor.
    * @param other Another MemoryRegionIterator to move.
    */
    explicit MemoryRegionIterator(MemoryRegionIterator&& other);

    /**
     * Destructor.
     */
    ~MemoryRegionIterator();

    /**
    * Move-Assignment.
    * @param other Another MemoryRegionIterator to move.
    */
    MemoryRegionIterator& operator=(MemoryRegionIterator&& other);

    /**
    * Checks if the iterator is (still) valid.
    * @return True if valid, else otherwise.
    */
    bool isValid() const;
  };

  typedef std::pair<MemoryRegionIterator, MemoryRegionIterator>
            MemoryRegionSequence;

  /**
  * Enumerates all memory regions of a process.
  * @param process The process.
  * @param f Functor to be called every entry with MemoryRegion as argument.
  * @return The functor f.
  */
  template<typename functor_t>
  functor_t enumMemoryRegions(Process const& process, functor_t f)
  {
    return std::for_each(
            MemoryRegionIterator(process), MemoryRegionIterator(), f);
  }

  /**
  * Makes a pair of MemoryRegionIterators, which can be used to iterate
  * memory regions of a process.
  * @param process The process.
  * @return A pair of MemoryRegionIterators.
  */
  MemoryRegionSequence makeMemoryRegionSequence(Process const& process);
  
  /**
  * Retrieves the memory region an address is inside.
  * @param process The process.
  * @param address Address to query for.
  * @return The memory-region, if found.
  */
  boost::optional<MemoryRegion> getMatchingRegion(Process const& process,
    std::uintptr_t address);
}

#endif //__ETHON_MEMORYREGIONS_HPP__