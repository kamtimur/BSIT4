#define _CRT_SECURE_NO_WARNINGS 
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#define _WIN32_DCOM
#define ONE p = (char **)*p;
#define UNICODE
using namespace std;

HRESULT hres;
IWbemLocator *pLoc = NULL;
IWbemServices *pSvc = NULL;
wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
bool useToken = false;


int Wmi_Request(wchar_t *nameSpace, bstr_t query, bstr_t attribute);

int main()
{
	wchar_t serv[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t cimv2[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t secur[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	cout << "Enter server name with \\\\" << endl;
	wcin >> serv;

	wcscat(serv, L"\\root\\");

	wcscpy(cimv2, serv);
	wcscat(cimv2, L"cimv2");

	wcscpy(secur, serv);
	wcscat(secur, L"SecurityCenter2");

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);// Инициализация COM.
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x"
			<< hex << hres << endl;
		return 1;
	}

	hres = CoInitializeSecurity( // Установка уровней безопасности COM
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT, //определение уровня идентификации по дефолту
		RPC_C_IMP_LEVEL_IDENTIFY,//уровень имперсонализации
		NULL,
		EOAC_NONE,//не установлено никаких дополнительных возможностей
		NULL
	);
	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;
	}

	hres = CoCreateInstance( // Создание локатора Wmi_Request
		CLSID_WbemLocator,
		0,//объект не часть совокупности
		CLSCTX_INPROC_SERVER, //внутри процесса
		IID_IWbemLocator, (LPVOID *)&pLoc); //интерфейс для связи с объектом
	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;
	}

	CREDUI_INFO cui; //информация для аутентификации

	BOOL fSave;
	DWORD dwErr;
	memset(&cui, 0, sizeof(CREDUI_INFO));
	cui.cbSize = sizeof(CREDUI_INFO); //размер структуры
	cui.hwndParent = NULL; //родительское окно - рабочий стол
	cui.pszMessageText = TEXT("Press cancel to use process token"); //сообщение в открывающимся окне
	cui.pszCaptionText = TEXT("Enter Account Information");//зпголовок диалогового окна
	cui.hbmBanner = NULL; //изображение для окна
	fSave = FALSE;
	dwErr = CredUIPromptForCredentials( // Получение реквизитов доступа к удаленному компьютеру
		&cui,
		TEXT(""),//имя сервера
		NULL, //режим сбора ошибок
		0,
		pszName,//имя пользователя
		CREDUI_MAX_USERNAME_LENGTH + 1,//длина имени пользователя
		pszPwd, //пароль
		CREDUI_MAX_PASSWORD_LENGTH + 1,//длина пароля
		&fSave,//начальное значение флага "сохранить"
		CREDUI_FLAGS_GENERIC_CREDENTIALS |//данные,введенные пользователем, общие
		CREDUI_FLAGS_ALWAYS_SHOW_UI |//всегда открывать пользовательский интерфейс
		CREDUI_FLAGS_DO_NOT_PERSIST);//не хранить учетные данные и не отображать флажки
	if (dwErr == ERROR_CANCELLED)//если пользователь выбрал "Отмена". имя и пароль не изменились
	{
		useToken = true;
	}
	else if (dwErr)
	{
		cout << "Did not get credentials " << dwErr << endl;
		pLoc->Release();
		CoUninitialize();
	}

	Wmi_Request(cimv2, "Select * from Win32_OperatingSystem", "RegisteredUser");
	Wmi_Request(cimv2, "Select * from Win32_OperatingSystem", "Version");
	Wmi_Request(cimv2, "Select * from Win32_PhysicalMemory ", "Attributes");
	Wmi_Request(cimv2, "Select * from Win32_PhysicalMemory ", "BankLabel");
	Wmi_Request(cimv2, "Select * from Win32_PhysicalMemory ", "Capacity");
	Wmi_Request(cimv2, "Select * from Win32_NetworkClient ", "Description");
	Wmi_Request(cimv2, "Select * from Win32_Product", "Name");
	Wmi_Request(cimv2, "Select * from Win32_Printer", "Name");
	Wmi_Request(cimv2, "Select * from Win32_Process Where Priority > 5", "Name");
	Wmi_Request(cimv2, "Select * from Win32_Service", "Name");
	//Wmi_Request(cimv2, "Select * from Win32_DiskDrive  ", "Availability");
	Wmi_Request(cimv2, "Select * from Win32_DiskDrive  ", "Description");
	Wmi_Request(cimv2, "Select * from Win32_DiskDrive  ", "DeviceID");
	Wmi_Request(cimv2, "Select * From Win32_ComputerSystem", "Name");
	Wmi_Request(secur, "Select * from AntiSpywareProduct", "displayName");

	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

}

int Wmi_Request(wchar_t *nameSpace, bstr_t query, bstr_t attribute) {
	// change the computerName strings below to the full computer name
	// of the remote computer
	wcout << endl << query << " & " << nameSpace << " & " << attribute << endl;

	hres = pLoc->ConnectServer(// Подключение к пространству имен root\...
		_bstr_t(nameSpace),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		NULL,
		NULL,
		&pSvc
	);
	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
	wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];

	COAUTHIDENTITY authIdent; // Создание структуры COAUTHIDENTITY
	COAUTHIDENTITY *userAcct = NULL;
	if (!useToken)
	{
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;
		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL)
		{
			cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}
		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);

		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);
		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName,
			slash - pszName);

		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		userAcct = &authIdent;
	}

	hres = CoSetProxyBlanket(// Установка защиты прокси сервера 
		pSvc,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	// Шаг 7: --------------------------------------------------
	// Получение данных через Wmi_Request ----
	// Например, получим имя ОС
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		query,//bstr_t("Select * from Win32_OperatingSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator) // Получение данных из запроса
	{

		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;

		hr = pclsObj->Get(attribute, 0, &vtProp, 0, 0);// Выбираем нужное поле
		locale::global(locale("en_US.UTF-8"));
		wcout << vtProp.bstrVal << endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	pEnumerator->Release();
	if (pclsObj)
	{
		pclsObj->Release();
	}

	return 0;
}