#pragma once

/*****************************************************************************
 * MainWindow declaration
 ****************************************************************************/

class MainWindow : public Fl_Window {
public:
    MainWindow(const char* title);
    virtual ~MainWindow() { }

    void show(int argc, char** argv);

private:
    InjectionMethod GetSelectedInjectionMethod();

    void Inject();
    void SelectInjectionMethod();
    void RescanDlls();

    void SelectDll(const std::string& dllName);

    static void InjectCallback(Fl_Widget* w, void* ptr);
    static void SelectInjectionMethodCallback(Fl_Widget* w, void* ptr);
    static void ExitCallback(Fl_Widget* /*w*/, void* /*ptr*/);
    static void RescanDllsCallback(Fl_Widget* /*w*/, void* /*ptr*/);

private:
    std::filesystem::path moduleDir;

    Fl_Input* inputName = nullptr;
    Fl_Radio_Round_Button* selectCreateThread = nullptr;
    Fl_Radio_Round_Button* selectSetThreatContext = nullptr;
    Fl_Radio_Round_Button* selectUserQueueApc = nullptr;
    Fl_Radio_Round_Button* selectSetWindowsHook = nullptr;
    Fl_Choice* choiceCreateThreadType = nullptr;
    Fl_Choice* choiceSetWindowsHook = nullptr;
    Fl_Choice* dllChoice = nullptr;
    Fl_Text_Buffer* logBuffer = nullptr;
    Fl_Text_Display* output = nullptr;
};
