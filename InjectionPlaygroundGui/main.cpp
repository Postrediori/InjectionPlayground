#include "pch.h"
#include "Utils.h"
#include "InjectionMethods.h"
#include "InjectionSetWindowsHookEx.h"
#include "MainWindow.h"


#ifdef _WIN64
const std::string WindowTitle = "Injection Playground x64";
#else
#  ifdef _WIN32
const std::string WindowTitle = "Injection Playground x86";
#  else
#    error Unknown architecture
#  endif
#endif


/*****************************************************************************
 * Main program
 ****************************************************************************/

int main(int argc, char** argv) {
    Fl::scheme("gtk+");

    auto wind = new MainWindow(WindowTitle.c_str());
    wind->show(argc, argv);

    return Fl::run();
}
