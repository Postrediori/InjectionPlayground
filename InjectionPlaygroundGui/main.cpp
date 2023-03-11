#include "pch.h"
#include "Utils.h"
#include "InjectionMethods.h"
#include "InjectionSetWindowsHookEx.h"


#ifdef _WIN64
const std::filesystem::path DefaultDllName = L"InjectedDll.x64.dll";
const std::filesystem::path WindowsHookDllName = L"WindowsHookDll.x64.dll";
#else
#  ifdef _WIN32
const std::filesystem::path DefaultDllName = L"InjectedDll.x86.dll";
const std::filesystem::path WindowsHookDllName = L"WindowsHookDll.x86.dll";
#  else
#    error Unknown architecture
#  endif
#endif

constexpr int WindowWidth = 640;
constexpr int WindowHeight = 480;

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
 * Inject into processes by name
 ****************************************************************************/

bool InjectToProcessesByName(std::ostream& log, const std::filesystem::path& processName, const std::filesystem::path& dllPath,
    InjectionMethod method, int hookType = 0) {

    wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        LogErrorLn(L"CreateToolhelp32Snapshot");
        return false;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    log << "Injecting with method " << ToAsciiString(GetInjectionMethodName(method)) << std::endl;
    if (method == InjectionMethod::SetWindowsHookInjection) {
        auto hookMethodDescription = std::find_if(SetWindowsHookValues.begin(), SetWindowsHookValues.end(),
            [=](const std::tuple<std::wstring, int>& info) {
                return std::get<1>(info) == hookType;
            });

        if (hookMethodDescription == SetWindowsHookValues.end()) {
            log << "Error: Unknown injection hook id " << hookType << std::endl;
            return false;
        }

        log << "Setting hook for message " << ToAsciiString(std::get<0>(*hookMethodDescription)) << std::endl;
    }
    log << "Looking for processes with name '" << processName.string() << "'" << std::endl;

    std::vector<DWORD> injectedProcesses;
    while (Process32NextW(snapshot.get(), (LPPROCESSENTRY32W)&pe)) {
        if (!CaseInsensitiveEqual(pe.szExeFile, processName.wstring())) {
            continue;
        }

        DWORD dwProcessId = pe.th32ProcessID;
        if (std::find(injectedProcesses.begin(), injectedProcesses.end(), dwProcessId) != injectedProcesses.end()) {
            continue;
        }

        log << "  " << "Process ID=" << dwProcessId << " ... ";
        if (InjectIntoProcessDll(dwProcessId, dllPath.wstring(), method, hookType)) {
            log << "OK";
        }
        else {
            log << " FAILED";
        }
        log << std::endl;

        injectedProcesses.push_back(dwProcessId);
    }

    if (injectedProcesses.empty()) {
        log << "No process with name " << processName << " was found" << std::endl;
    }

    return true;
}


/*****************************************************************************
 * MainWindow declaration
 ****************************************************************************/

class MainWindow : public Fl_Window {
public:
    MainWindow(int w, int h, const char* title);
    virtual ~MainWindow() { }

    void show(int argc, char** argv);

private:
    InjectionMethod GetSelectedInjectionMethod();

    void Inject();
    void SelectInjectionMethod();

    static void InjectCallback(Fl_Widget* w, void* ptr);
    static void SelectInjectionMethodCallback(Fl_Widget* w, void* ptr);

private:
    std::filesystem::path moduleDir;

    Fl_Group* paramsGroup = nullptr;
    Fl_Input* inputName = nullptr;
    Fl_Radio_Round_Button* selectCreateThread = nullptr;
    Fl_Radio_Round_Button* selectSetThreatContext = nullptr;
    Fl_Radio_Round_Button* selectUserQueueApc = nullptr;
    Fl_Radio_Round_Button* selectSetWindowsHook = nullptr;
    Fl_Choice* choiceCreateThreadType = nullptr;
    Fl_Choice* choiceSetWindowsHook = nullptr;
    Fl_Text_Buffer* logBuffer = nullptr;
    Fl_Text_Display* output = nullptr;
};


/*****************************************************************************
 * MainWindow methods
 ****************************************************************************/

MainWindow::MainWindow(int w, int h, const char* title)
    : Fl_Window(w, h, title) {

    begin();

    inputName = new Fl_Input(150, 10, 400, 25, "Process name:");
    inputName->value("ProcessName.exe");

    paramsGroup = new Fl_Group(150, 55, 400, 165, "Injection parameters");
    paramsGroup->color(FL_GRAY + 4);
    paramsGroup->box(FL_FRAME_BOX);
    paramsGroup->begin();

    selectCreateThread = new Fl_Radio_Round_Button(paramsGroup->x() + 25, paramsGroup->y() + 25, 150, 25, "Create Thread");
    selectCreateThread->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));

    selectSetThreatContext = new Fl_Radio_Round_Button(paramsGroup->x() + 25, paramsGroup->y() + 55, 150, 25, "SetThreadContext");
    selectSetThreatContext->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));

    selectUserQueueApc = new Fl_Radio_Round_Button(paramsGroup->x() + 25, paramsGroup->y() + 85, 150, 25, "UserQueueApc");
    selectUserQueueApc->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));

    selectSetWindowsHook = new Fl_Radio_Round_Button(paramsGroup->x() + 25, paramsGroup->y() + 115, 150, 25, "SetWindowsHook");
    selectSetWindowsHook->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));

    choiceCreateThreadType = new Fl_Choice(selectCreateThread->x() + selectCreateThread->w() + 25, selectCreateThread->y(), 175, 25, "Method:");
    choiceCreateThreadType->add("CreateRemoteThread");
    choiceCreateThreadType->add("RtlCreateUserThread");
    choiceCreateThreadType->add("NtCreateThreadEx");

    choiceSetWindowsHook = new Fl_Choice(selectSetWindowsHook->x() + selectSetWindowsHook->w() + 25, selectSetWindowsHook->y(), 175, 25, "Hook:");
    int defaultHookChoice = 0, k = 0;
    for (const auto& info : SetWindowsHookValues) {
        auto s = ToAsciiString(std::get<0>(info));
        choiceSetWindowsHook->add(s.c_str());

        if (std::get<1>(info) == DefaultWindowHookId) {
            defaultHookChoice = k;
        }
        k++;
    }

    selectCreateThread->value(1);
    choiceCreateThreadType->value(0);
    choiceSetWindowsHook->value(defaultHookChoice);
    SelectInjectionMethod();

    paramsGroup->end();

    auto injectButton = new Fl_Button(150, paramsGroup->y() + paramsGroup->h() + 15, 75, 25, "Inject");
    injectButton->callback(MainWindow::InjectCallback, static_cast<void*>(this));

    logBuffer = new Fl_Text_Buffer();

    output = new Fl_Text_Display(150, injectButton->y() + injectButton->h() + 15, 400, 150, "Injection Log");
    output->buffer(logBuffer);

    end();
}

void MainWindow::show(int argc, char** argv) {
    moduleDir = std::filesystem::canonical(std::filesystem::path(argv[0])).parent_path();

    Fl_Window::show(argc, argv);
}

InjectionMethod MainWindow::GetSelectedInjectionMethod() {
    if (selectCreateThread->value() == 1) {
        switch (choiceCreateThreadType->value()) {
        case 0:
            return InjectionMethod::CreateRemoteThread;
        case 1:
            return InjectionMethod::RtlCreateUserThread;
        case 2:
            return InjectionMethod::NtCreateThreadEx;
        default:
            break;
        }
    }
    else if (selectSetThreatContext->value() == 1) {
        return InjectionMethod::SetThreadContext;
    }
    else if (selectUserQueueApc->value() == 1) {
        return InjectionMethod::QueueUserApc;
    }
    else if (selectSetWindowsHook->value() == 1) {
        return InjectionMethod::SetWindowsHookInjection;
    }
    
    // Inaccessible
    throw std::runtime_error("Unknown injection setting");

    return InjectionMethod::CreateRemoteThread;
}

void MainWindow::Inject() {
    auto method = GetSelectedInjectionMethod();
    auto hookId = (method == InjectionMethod::SetWindowsHookInjection) ?
        std::get<1>(SetWindowsHookValues.at(choiceSetWindowsHook->value())) : 0;

    auto dllName = (method == InjectionMethod::SetWindowsHookInjection) ?
        WindowsHookDllName : DefaultDllName;

    std::filesystem::path processName(inputName->value());
    std::filesystem::path dllPath = moduleDir / dllName;

    std::stringstream log;
    InjectToProcessesByName(log, processName, dllPath, method, hookId);

    int topLine = logBuffer->count_lines(0, logBuffer->length());

    std::cout << log.str();
    logBuffer->append(log.str().c_str());
    output->scroll(topLine + 1, 0);
}

void MainWindow::SelectInjectionMethod() {
    if (selectCreateThread->value() == 1) {
        choiceCreateThreadType->activate();
    }
    else {
        choiceCreateThreadType->deactivate();
    }

    if (selectSetWindowsHook->value() == 1) {
        choiceSetWindowsHook->activate();
    }
    else {
        choiceSetWindowsHook->deactivate();
    }
}

void MainWindow::InjectCallback(Fl_Widget* w, void* ptr) {
    auto wind = reinterpret_cast<MainWindow*>(ptr);
    wind->Inject();
}

void MainWindow::SelectInjectionMethodCallback(Fl_Widget* w, void* ptr) {
    auto wind = reinterpret_cast<MainWindow*>(ptr);
    wind->SelectInjectionMethod();
}


/*****************************************************************************
 * Main program
 ****************************************************************************/

int main(int argc, char** argv) {
    Fl::scheme("gtk+");

    auto wind = new MainWindow(WindowWidth, WindowHeight, WindowTitle.c_str());
    wind->show(argc, argv);

    return Fl::run();
}
