#include "pch.h"
#include "Utils.h"
#include "InjectionMethods.h"
#include "InjectionSetWindowsHookEx.h"
#include "InjectionUtils.h"
#include "MainWindow.h"

constexpr int WindowWidth = 515;
constexpr int WindowHeight = 480;

constexpr int Margin = 10;

const std::string DefaultProcessName = "ProcessName.exe";

/*****************************************************************************
 * MainWindow methods
 ****************************************************************************/

MainWindow::MainWindow(const char* title)
    : Fl_Window(WindowWidth, WindowHeight, title) {

    begin();

    auto pack = new Fl_Flex(Margin, Margin, w() - Margin * 2, h() - Margin * 2, Fl_Flex::VERTICAL);
    pack->spacing(Margin);

    {
        auto row = new Fl_Flex(Fl_Flex::HORIZONTAL);

        auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
        row->fixed(spacer, 125);

        inputName = new Fl_Input(0, 0, 275, 25, "Process name:");
        inputName->value(DefaultProcessName.c_str());
        
        row->resizable(inputName);

        row->end();
        pack->fixed(row, 25);
    }

    {
        auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
        pack->fixed(spacer, Margin);
    }

    {
        auto paramsGroup = new Fl_Group(0, 0, 400, 165, "Injection type");
        paramsGroup->color(FL_GRAY + 4);
        paramsGroup->box(FL_FRAME_BOX);
        paramsGroup->begin();

        auto row = new Fl_Flex(0, 0, paramsGroup->w(), paramsGroup->h(), Fl_Flex::HORIZONTAL);
        row->spacing(Margin);
        row->margin(Margin);

        {
            auto column = new Fl_Flex(0, 0, 100, 100, Fl_Flex::VERTICAL);
            column->spacing(Margin);
            column->margin(Margin);

            selectCreateThread = new Fl_Radio_Round_Button(0, 0, 150, 25, "Create Thread");
            selectCreateThread->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));
            column->fixed(selectCreateThread, 25);

            selectSetThreatContext = new Fl_Radio_Round_Button(0, 0, 150, 25, "SetThreadContext");
            selectSetThreatContext->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));
            column->fixed(selectSetThreatContext, 25);

            selectUserQueueApc = new Fl_Radio_Round_Button(0, 0, 150, 25, "UserQueueApc");
            selectUserQueueApc->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));
            column->fixed(selectUserQueueApc, 25);

            selectSetWindowsHook = new Fl_Radio_Round_Button(0, 0, 150, 25, "SetWindowsHook");
            selectSetWindowsHook->callback(MainWindow::SelectInjectionMethodCallback, static_cast<void*>(this));
            column->fixed(selectSetWindowsHook, 25);

            selectCreateThread->value(1);

            column->end();
            row->fixed(column, 175);
        }

        {
            auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 10, 10, "");
            row->resizable(spacer);
        }

        {
            auto column = new Fl_Flex(0, 0, 100, 25, Fl_Flex::VERTICAL);
            column->spacing(Margin);
            column->margin(Margin);

            choiceCreateThreadType = new Fl_Choice(0, 0, 175, 25, "Method:");
            choiceCreateThreadType->add("CreateRemoteThread");
            choiceCreateThreadType->add("RtlCreateUserThread");
            choiceCreateThreadType->add("NtCreateThreadEx");
            choiceCreateThreadType->value(0);
            column->fixed(choiceCreateThreadType, 25);

            {
                auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
                column->fixed(spacer, 25);
            }
            {
                auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
                column->fixed(spacer, 25);
            }

            choiceSetWindowsHook = new Fl_Choice(0, 0, 175, 25, "Hook:");
            int defaultHookChoice = 0, k = 0;
            for (const auto& info : SetWindowsHookValues) {
                auto s = ToAsciiString(std::get<0>(info));
                choiceSetWindowsHook->add(s.c_str());

                if (std::get<1>(info) == DefaultWindowHookId) {
                    defaultHookChoice = k;
                }
                k++;
            }
            column->fixed(choiceSetWindowsHook, 25);
            choiceSetWindowsHook->value(defaultHookChoice);

            column->end();
            row->fixed(column, 195);
        }

        row->end();

        paramsGroup->end();

        pack->fixed(paramsGroup, 165);
    }

    {
        auto row = new Fl_Flex(Fl_Flex::HORIZONTAL);
        row->spacing(Margin);

        auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
        row->fixed(spacer, 125);

        dllChoice = new Fl_Choice(0, 0, 275, 25, "Injection DLL:");

        auto rescanButton = new Fl_Button(0, 0, 75, 25, "Rescan DLLs");
        rescanButton->callback(MainWindow::RescanDllsCallback, static_cast<void*>(this));
        row->fixed(rescanButton, 95);

        row->resizable(dllChoice);

        row->end();
        pack->fixed(row, 25);
    }

    {
        auto row = new Fl_Flex(Fl_Pack::HORIZONTAL);
        row->spacing(Margin);

        auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
        pack->resizable(spacer);

        auto injectButton = new Fl_Button(0, 0, 75, 25, "Inject");
        injectButton->callback(MainWindow::InjectCallback, static_cast<void*>(this));
        row->fixed(injectButton, 75);

        auto closeButton = new Fl_Button(0, 0, 75, 25, "Close");
        closeButton->callback(MainWindow::ExitCallback);
        row->fixed(closeButton, 75);

        row->end();
        pack->fixed(row, 25);
    }

    {
        auto spacer = new Fl_Box(FL_NO_BOX, 0, 0, 125, 25, "");
        pack->fixed(spacer, Margin);
    }

    {
        logBuffer = new Fl_Text_Buffer();

        output = new Fl_Text_Display(0, 0, 400, 150, "Injection Log");
        output->buffer(logBuffer);
    }

    pack->end();

    resizable(pack);

    end();

    RescanDlls();
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

    auto item = dllChoice->mvalue();
    auto dllName = std::string(item->text);

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

    if (selectSetWindowsHook->value() == 0) {
        choiceSetWindowsHook->deactivate();
        SelectDll(DefaultDllName.string());
    }
    else {
        choiceSetWindowsHook->activate();
        SelectDll(WindowsHookDllName.string());
    }
}

void MainWindow::RescanDlls() {
    const std::filesystem::path DllExtension = ".dll";
    const std::vector<std::filesystem::path> StandardDlls = {
        DefaultDllName,
        WindowsHookDllName
    };

    // Scan for all DLLs in current directory
    std::vector<std::filesystem::path> foundStandardDlls; // DLLs required for standard injection
    std::vector<std::filesystem::path> foundDlls; // The rest of DLLs

    const auto current_directory{ std::filesystem::current_path() };
    std::cout << "Scanning for DLLs in directory " << current_directory << std::endl;
    for (auto const& dir_entry : std::filesystem::directory_iterator{ current_directory }) {
        const auto path = dir_entry.path();
        if (!std::filesystem::is_directory(path) && path.has_extension() && (path.extension() == DllExtension)) {
            const auto filename = path.filename();
            std::cout << "Found DLL " << filename << std::endl;

            if (std::find(StandardDlls.begin(), StandardDlls.end(), filename) != StandardDlls.end()) {
                foundStandardDlls.push_back(filename);
            }
            else {
                foundDlls.push_back(filename);
            }
        }
    }

    // Add standard DLLs to the beginning
    for (const auto& s : StandardDlls) {
        // Check if standard DLL is in the found list
        if (std::find(foundStandardDlls.begin(), foundStandardDlls.end(), s) != foundStandardDlls.end()) {
            dllChoice->add(s.string().c_str());
        }
        else {
            std::cerr << "Error: Unable to find required DLL " << s << std::endl;
        }
    }

    // Look for the rest
    for (const auto& f : foundDlls) {
        dllChoice->add(f.string().c_str());
    }

    SelectInjectionMethod(); // Select DLL based on current injection mode
}

void MainWindow::SelectDll(const std::string& dllName) {
    int k = dllChoice->find_index(dllName.c_str());
    if (k != -1) {
        dllChoice->value(k);
    }
    else {
        std::cerr << "Error: Unable to find DLL " << dllName << " in the list" << std::endl;
    }
}

void MainWindow::InjectCallback(Fl_Widget* w, void* ptr) {
    auto wind = reinterpret_cast<MainWindow*>(ptr);
    wind->Inject();
}

void MainWindow::ExitCallback(Fl_Widget* /*w*/, void* /*ptr*/) {
    exit(0);
}

void MainWindow::SelectInjectionMethodCallback(Fl_Widget* w, void* ptr) {
    auto wind = reinterpret_cast<MainWindow*>(ptr);
    wind->SelectInjectionMethod();
}

void MainWindow::RescanDllsCallback(Fl_Widget* w, void* ptr) {
    auto wind = reinterpret_cast<MainWindow*>(ptr);
    wind->RescanDlls();
}
