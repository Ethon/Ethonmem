/*
ProcessLock.hpp
This File is a part of Ethonmem, a memory hacking library for linux
Copyright (C) < 2012, Ethon >
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

#ifndef HEADER_UUID_518253E78312461FA1368B8DF8022E0F
#define HEADER_UUID_518253E78312461FA1368B8DF8022E0F

namespace Ethon
{
	class Debugger;
	
	/**
	 * @brief Locks the current process for memory manipulations.
	 */
	class ProcessLock
	{
	private:
		Debugger& m_debugger;
		bool m_wasLocked;
		
	public:
		/**
		 * @brief Initialize the lock with a debugger.
		 * 
		 * @param debugger A Debugger debugging the target process. The caller
		 * is responsible to ensure that the Debugger object's lifetime
		 * exceeds the lock's lifetime.
		 */
		ProcessLock(Debugger& debugger);
		
		/**
		 * @brief Unlock the target process upon lock destruction. 
		 */
		~ProcessLock();
		
		// Forbid copying the lock.
		ProcessLock(ProcessLock const&) = delete;
		ProcessLock& operator=(ProcessLock const&) = delete;
	};
}

#endif // HEADER_UUID_518253E78312461FA1368B8DF8022E0F
