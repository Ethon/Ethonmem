/*
ProcessLock.cpp
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

// Ethon:
#include <Ethon/ProcessLock.hpp>
#include <Ethon/Debugger.hpp>

Ethon::ProcessLock::ProcessLock(Ethon::Debugger& debugger)
	: m_debugger(debugger), m_wasStopped()
{
	Ethon::ProcessStatus status;
	debugger.getProcess().getStatus(status);
	m_wasStopped = status.isStopped();
	if(!m_wasStopped)
		debugger.stop();
}
		
Ethon::~ProcessLock()
{
	if(!m_wasStopped)
		m_debugger.cont();
}
