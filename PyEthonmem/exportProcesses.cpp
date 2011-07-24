// Boost Header Files:
#include <boost/python.hpp>
#include <boost/foreach.hpp>

// Ethon Header Files:
#include <Ethon/Processes.hpp>

boost::python::str Process__getExecutablePath(Ethon::Process* proc)
{
  return boost::python::str(proc->getExecutablePath().string().c_str());
}

boost::python::str Process__getProcfsDirectory(Ethon::Process* proc)
{
  return boost::python::str(proc->getProcfsDirectory().string().c_str());
}

Ethon::ProcessStatus Process__getStatus(Ethon::Process* proc)
{
  return proc->getStatus();
}

boost::python::str ProcessStatus__getExecutableName(Ethon::ProcessStatus* status)
{
  return boost::python::str(status->getExecutableName().c_str());
}

Ethon::Process getCurrentProcess()
{
  return Ethon::getCurrentProcess();
}

boost::python::object getProcessByName(std::string name)
{
  auto proc = Ethon::getProcessByName(name);
  if(proc)
    return boost::python::object(*proc);

  return boost::python::object();
}

boost::python::list getProcessListByName(std::string name)
{
  boost::python::list result;

  auto list = Ethon::getProcessListByName(name);
  BOOST_FOREACH(Ethon::Process const& cur, list)
      result.append(cur);

  return result;
}

void exportProcesses()
{
  boost::python::class_<std::pair<int, int>>("DeviceNumber")
    .add_property("major", &std::pair<int, int>::first)
    .add_property("minor", &std::pair<int, int>::second)
  ;

  boost::python::class_<Ethon::ProcessStatus>("ProcessStatus")
    .def("getPid", &Ethon::ProcessStatus::getPid)
    .def("getExecutableName", &ProcessStatus__getExecutableName)
    .def("isRunning", &Ethon::ProcessStatus::isRunning)
    .def("isSleeping", &Ethon::ProcessStatus::isSleeping)
    .def("isWaiting", &Ethon::ProcessStatus::isWaiting)
    .def("isZombie", &Ethon::ProcessStatus::isZombie)
    .def("isStopped", &Ethon::ProcessStatus::isStopped)
    .def("isPaging", &Ethon::ProcessStatus::isPaging)
    .def("getState", &Ethon::ProcessStatus::getState)
    .def("getStateString", &Ethon::ProcessStatus::getStateString)
    .def("getParentPid", &Ethon::ProcessStatus::getParentPid)
    .def("getProcessGroupId", &Ethon::ProcessStatus::getProcessGroupId)
    .def("getSessionId", &Ethon::ProcessStatus::getSessionId)
    .def("getTty", &Ethon::ProcessStatus::getTty)
    .def("getTtyProcessGroupId", &Ethon::ProcessStatus::getTtyProcessGroupId)
    .def("getKernelFlagsWord", &Ethon::ProcessStatus::getKernelFlagsWord)
    .def("getNumMinorFaults", &Ethon::ProcessStatus::getNumMinorFaults)
    .def("getNumChildrenMinorFaults", &Ethon::ProcessStatus::getNumChildrenMinorFaults)
    .def("getNumMajorFaults", &Ethon::ProcessStatus::getNumMajorFaults)
    .def("getNumChildrenMajorFaults", &Ethon::ProcessStatus::getNumChildrenMajorFaults)
    .def("getUserTime", &Ethon::ProcessStatus::getUserTime)
    .def("getSystemTime", &Ethon::ProcessStatus::getSystemTime)
    .def("getChildrenUserTime", &Ethon::ProcessStatus::getChildrenUserTime)
    .def("getChildrenSystemTime", &Ethon::ProcessStatus::getChildrenSystemTime)
    .def("getPriority", &Ethon::ProcessStatus::getPriority)
    .def("getNice", &Ethon::ProcessStatus::getNice)
    .def("getNumThreads", &Ethon::ProcessStatus::getNumThreads)
    .def("getStartTime", &Ethon::ProcessStatus::getStartTime)
    .def("getVirtualMemorySize", &Ethon::ProcessStatus::getVirtualMemorySize)
    .def("getResidentSetSize", &Ethon::ProcessStatus::getResidentSetSize)
    .def("getResidentSetLimit", &Ethon::ProcessStatus::getResidentSetLimit)
    .def("getCodeStart", &Ethon::ProcessStatus::getCodeStart)
    .def("getCodeEnd", &Ethon::ProcessStatus::getCodeEnd)
    .def("getStackStart", &Ethon::ProcessStatus::getStackStart)
    .def("getStackPointer", &Ethon::ProcessStatus::getStackPointer)
    .def("getInstructionPointer", &Ethon::ProcessStatus::getInstructionPointer)
    .def("getWaitChannel", &Ethon::ProcessStatus::getWaitChannel)
    .def("getExitSignal", &Ethon::ProcessStatus::getExitSignal)
    .def("getCpuNumber", &Ethon::ProcessStatus::getCpuNumber)
    .def("getRealtimePriority", &Ethon::ProcessStatus::getRealtimePriority)
    .def("getSchedulingPolicy", &Ethon::ProcessStatus::getSchedulingPolicy)
    .def("getIoDelays", &Ethon::ProcessStatus::getIoDelays)
    .def("getGuestTime", &Ethon::ProcessStatus::getGuestTime)
    .def("getChildrenGuestTime", &Ethon::ProcessStatus::getChildrenGuestTime)
  ;

  boost::python::class_<Ethon::Process>("Process")
    .def(boost::python::init<Ethon::Pid>())
    .def("getPid", &Ethon::Process::getPid)
    .def("getExecutablePath", &Process__getExecutablePath)
    .def("getProcfsDirectory", &Process__getProcfsDirectory)
    .def("getStatus", &Process__getStatus)
  ;

  boost::python::def("enumProcesses", &Ethon::enumProcesses<boost::python::object>);
  boost::python::def("getCurrentProcess", &getCurrentProcess);
  boost::python::def("getProcessByName", &getProcessByName);
  boost::python::def("getProcessListByName", &getProcessListByName);
  boost::python::def("getProcessImageBits", &Ethon::getProcessImageBits);
}

