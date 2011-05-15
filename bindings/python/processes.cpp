#include <boost/python.hpp>
#include <Ethon/Processes.hpp>

using namespace boost::python;

BOOST_PYTHON_MODULE(ethonmem)
{
  class_<Ethon::ProcessStatus>("ProcessStatus")
    .def("read", &Ethon::ProcessStaus::read)
    ;
    
  class_<Ethon::Process>("Process")
    .def(init<Ethon::Pid>())
    .add_property("pid", &Ethon::Process::getPid)
    .add_property("executablePath", &Ethon::Process::getExecutablePath)
    .add_property("procfsDirectory", &Ethon::Process::getProcfsDirectory)
    ;
}
