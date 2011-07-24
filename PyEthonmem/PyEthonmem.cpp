// Boost Header Files:
#include <boost/python.hpp>

extern void exportProcesses();

BOOST_PYTHON_MODULE(Ethonmem)
{
  exportProcesses();
}
