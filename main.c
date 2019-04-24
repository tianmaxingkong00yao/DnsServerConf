#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <Wbemidl.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define SYSMGR_NAMESPACE L"root\\cimv2"
#define CONF_FILENAME L"dns-conf.ini"

typedef struct ComInstance_ {
	IWbemLocator *locator;
	IWbemServices *services;
} ComInstance;

typedef struct WbemMethod_
{
	ComInstance *instance;
	BSTR method_name;
} WbemMethod;

typedef struct DnsHost_
{
	WCHAR name[64];
} DnsHost;

typedef struct DnsServConf_
{
	int num_host;
	DnsHost *host;
} DnsServConf;


DWORD Win32FromHResult(HRESULT hr)
{
	if ((hr & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
	{
		return HRESULT_CODE(hr);
	}

	if (hr == S_OK)
	{
		return ERROR_SUCCESS;
	}

	// Not a Win32 HRESULT so return a generic error code.
	return ERROR_CAN_NOT_COMPLETE;
}

/**
 *  Creates a COM instance connected to the specified resource
 */
HRESULT ComInstanceInit(ComInstance *instance, LPCWSTR resource)
{
	HRESULT hr = S_OK;
	BSTR resource_bstr;

	instance->locator = NULL;
	instance->services = NULL;

	resource_bstr = SysAllocString(resource);
	if (resource_bstr == NULL) {
		return E_OUTOFMEMORY;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_SECURE_REFS, NULL);
	if (hr != S_OK) {

		goto release;
	}

	/* connect to WMI */
	hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
		&IID_IWbemLocator, (LPVOID *)&instance->locator);
	if (hr != S_OK) {
		goto release;
	}

	hr = instance->locator->lpVtbl->ConnectServer(
		instance->locator, resource_bstr, NULL, NULL, NULL, 0, NULL, NULL,
		&instance->services);
	if (hr != S_OK) {
		printf("ConnectServer failed: %s\n", FormatErrMsg(Win32FromHResult(hr)));
	}

release:

	if (hr != S_OK)
	{
		if (instance->locator)
		{
			instance->locator->lpVtbl->Release(instance->locator);
			instance->locator = NULL;
		}

		if (instance->services)
		{
			instance->services->lpVtbl->Release(instance->services);
			instance->services = NULL;
		}

	}

	SysFreeString(resource_bstr);

	return hr;
}

void ComInstanceRelease(ComInstance *instance)
{
	instance->locator->lpVtbl->Release(instance->locator);
	instance->services->lpVtbl->Release(instance->services);
}

// obtains a class definition from COM services
HRESULT GetWbemClass(ComInstance *instance, LPCWSTR name,
	IWbemClassObject **p_class)
{
	HRESULT hr = WBEM_S_NO_ERROR;
	BSTR name_bstr = NULL;

	if (instance == NULL || name == NULL || p_class == NULL ||
		*p_class != NULL) {
		hr = HRESULT_FROM_WIN32(E_INVALIDARG);
		
		return hr;
	}

	/* allocate name string */
	name_bstr = SysAllocString(name);
	if (name_bstr == NULL) {
		hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
		
		return hr;
	}

	/* obtain object */
	hr = instance->services->lpVtbl->GetObject(instance->services, name_bstr,
		WBEM_FLAG_RETURN_WBEM_COMPLETE,
		NULL, p_class, NULL);

	SysFreeString(name_bstr);

	return hr;
}

// spawns an empty class instance of the specified type
HRESULT GetWbemClassInstance(ComInstance *instance, LPCWSTR name,
	IWbemClassObject **p_instance)
{
	HRESULT hr = WBEM_S_NO_ERROR;

	IWbemClassObject *objClass = NULL;

	hr = GetWbemClass(instance, name, &objClass);
	if (hr != WBEM_S_NO_ERROR) {
		return hr;
	}

	hr = objClass->lpVtbl->SpawnInstance(objClass, 0, p_instance);
	objClass->lpVtbl->Release(objClass);

	return hr;
}


int LocalHostIpv4String(LPWSTR lpszAddr, DWORD cchAddr)
{
	CHAR hname[MAX_PATH];
	struct hostent *hent;
	struct in_addr ip;

	gethostname(hname, MAX_PATH);

	hent = gethostbyname(hname);
	if (hent == NULL)
		return 0;

	ip.s_addr = *((unsigned *)hent->h_addr_list[0]);

	return MultiByteToWideChar(CP_ACP, 0, inet_ntoa(ip), -1, lpszAddr, cchAddr);
}

int IPAddressToString(SOCKADDR *addr, int addrLen, LPWSTR pString, int cchString)
{
	return GetNameInfoW(addr, addrLen, pString, cchString, NULL, 0, NI_NUMERICHOST);
}

int IPStringToAddress(int af, LPCWSTR pIpString, void *pOutBuf)
{
	ADDRINFOW hints, *result = NULL;
	int rc = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;

	rc = GetAddrInfoW(pIpString, NULL, &hints, &result);
	if (rc != 0)
		return rc;

	if (af == AF_INET)
	{
		SOCKADDR_IN *in = (SOCKADDR_IN *)result->ai_addr;

		memcpy(pOutBuf, &in->sin_addr, 4);
		
	}
	else if (af == AF_INET6)
	{
		SOCKADDR_IN6 *in6 = (SOCKADDR_IN6 *)result->ai_addr;

		memcpy(pOutBuf, &in6->sin6_addr, 16);
		
	}
	else
	{
		rc = ERROR_INVALID_DATATYPE;
	}

	FreeAddrInfoW(result);

	return rc;
}

DWORD GetAdapterGuidByAddr(LPCWSTR lpwszAddr, GUID *lpGuid,  PDWORD pdwIfIndex)
{
	ULONG rc = NO_ERROR;
	DWORD dwSize = sizeof(IP_ADAPTER_ADDRESSES);
	PIP_ADAPTER_ADDRESSES pAdaptsAddr = NULL;

	do {
		pAdaptsAddr = (PIP_ADAPTER_ADDRESSES)malloc(dwSize);
		if (!pAdaptsAddr)
		{
			rc = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		rc = GetAdaptersAddresses(AF_INET, 0, NULL, pAdaptsAddr, &dwSize);
		if (rc == ERROR_BUFFER_OVERFLOW)
		{
			free(pAdaptsAddr);
			pAdaptsAddr = NULL;
		}

	} while (rc == ERROR_BUFFER_OVERFLOW);

	if (rc == NO_ERROR)
	{
		PIP_ADAPTER_ADDRESSES pAddress = pAdaptsAddr;
		PIP_ADAPTER_UNICAST_ADDRESS pIpAddresses, pIpAddr;
		WCHAR wszIp[MAX_PATH];
		BOOL bFound = FALSE;

		for (; pAddress != NULL; pAddress = pAddress->Next)
		{
			pIpAddresses = pAddress->FirstUnicastAddress;

			for (pIpAddr = pIpAddresses; pIpAddr; pIpAddr = pIpAddr->Next)
			{
				IPAddressToString(pIpAddr->Address.lpSockaddr, pIpAddr->Address.iSockaddrLength, wszIp, MAX_PATH);
				if (!wcsncmp(wszIp, lpwszAddr, wcslen(lpwszAddr)))
				{
					bFound = TRUE;
					break;
				}
			}

			if (bFound)
			{
				WCHAR wszName[100];

				MultiByteToWideChar(CP_ACP, 0, pAddress->AdapterName, -1, wszName, 100);
				CLSIDFromString(wszName, lpGuid);
				*pdwIfIndex = pAddress->IfIndex;
				break;
			}
		}
	}

	if (pAdaptsAddr)
		free(pAdaptsAddr);

	return rc;
}

HRESULT FindAdapterClassById(IWbemServices *pServ, const GUID *pGuid, IWbemClassObject **pAdaptCfg)
{
	HRESULT hr;
	WCHAR wszGuid[50];
	WCHAR wszQuery[256];
	IEnumWbemClassObject *pEnum = NULL;
	BSTR bstr_wql = NULL, bstr_query = NULL;

	if (!StringFromGUID2(pGuid, wszGuid, _countof(wszGuid)))
		return E_INVALIDARG;

	swprintf_s(wszQuery,
		_countof(wszQuery),
		L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = \"%s\"",
		wszGuid);

	bstr_wql = SysAllocString(L"WQL");
	bstr_query = SysAllocString(wszQuery);
	if (!bstr_wql || !bstr_query)
	{
		hr = E_POINTER;
		goto release;
	}

	hr = pServ->lpVtbl->ExecQuery(pServ,
		bstr_wql,
		bstr_query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnum);
	if (hr == S_OK)
	{
		IWbemClassObject *pObject = NULL;
		DWORD dwReturn = 0;

		hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObject, &dwReturn);
		if (hr == S_OK)
		{
			if (dwReturn && pObject)
			{
				*pAdaptCfg = pObject;
			}
		}

		pEnum->lpVtbl->Release(pEnum);
	}

release:

	if (bstr_wql)
		SysFreeString(bstr_wql);

	if (bstr_query)
		SysFreeString(bstr_query);

	return hr;
}

HRESULT GetIpSettings(IWbemClassObject *pAdaptCfg, LPWSTR pIpv4, int cchIp, LPWSTR pMaskv4, int cchMask)
{
	VARIANT vtIp;
	HRESULT hr;

	VariantInit(&vtIp);

	hr = pAdaptCfg->lpVtbl->Get(pAdaptCfg, L"IPAddress", 0, &vtIp, NULL, NULL);
	if (hr != S_OK)
		return hr;

	if (vtIp.vt == (VT_ARRAY | VT_BSTR))
	{
		VARIANT vtMask;

		VariantInit(&vtMask);

		hr = pAdaptCfg->lpVtbl->Get(pAdaptCfg, L"IPSubnet", 0, &vtMask, NULL, NULL);
		if (hr == S_OK)
		{
			if (vtMask.vt == (VT_ARRAY | VT_BSTR))
			{
				SAFEARRAY *pIpArray = vtIp.parray;
				SAFEARRAY *pMaskArray = vtMask.parray;
				if (pIpArray && pMaskArray)
				{
					BSTR pCurIp;
					BSTR pCurMask;
					LONG i;

					for (i = 0;
						SafeArrayGetElement(pIpArray, &i, (PVOID)&pCurIp) == S_OK
						&& SafeArrayGetElement(pMaskArray, &i, (PVOID)&pCurMask) == S_OK;
						i++)
					{

						if (wcscmp(pCurIp, L"0.0.0.0"))
						{
							wcscpy_s(pIpv4, cchIp, pCurIp);
							wcscpy_s(pMaskv4, cchMask, pCurMask);

							break;
						}

					}
				}
			}
			else
			{
				hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATATYPE);
			}

			VariantClear(&vtMask);
		}
	}

	VariantClear(&vtIp);

	return hr;
}


HRESULT CreateIpArray(SAFEARRAY **ppArray, DnsHost *aIp, const ULONG cIp)
{
	LONG i = 0;
	HRESULT hr = S_OK;
	SAFEARRAY *pIpArray = SafeArrayCreateVector(VT_BSTR, 0, cIp);

	if (pIpArray == NULL)
		return HRESULT_FROM_WIN32(GetLastError());

	for (ULONG idx = 0; idx < cIp; idx++)
	{
		BSTR val;
		LONG aIndex[1];

		val = SysAllocString(aIp[idx].name);
		if (val == NULL)
		{
			hr = E_OUTOFMEMORY;
			break;
		}

		aIndex[0] = i;
		hr = SafeArrayPutElement(pIpArray, aIndex, val);
		if (hr != S_OK)
		{
			SysFreeString(val);
			break;
		}

		i++;
	}
	
	if (hr != S_OK)
	{
		SafeArrayDestroy(pIpArray);
	}
	else
	{
		*ppArray = pIpArray;
	}

	return hr;
}

HRESULT  CreateIpArrayVariantV4(VARIANT *pIpAddr, DnsHost *aIp, const ULONG cIp)
{
	HRESULT hr;
	SAFEARRAY *pIpArray;

	VariantInit(pIpAddr);

	pIpAddr->vt = VT_ARRAY | VT_BSTR;
	hr = CreateIpArray(&pIpArray, aIp, cIp);
	if (hr == S_OK)
	{
		pIpAddr->parray = pIpArray;
	}

	return hr;
}

HRESULT WbemExecMethod(
	IWbemServices *pServ,
	IWbemClassObject *pClass,
	BSTR ObjPath,
	BSTR MethodName,
	LPWSTR *pArgNames,
	VARIANT **pArgs,
	ULONG cArgs,
	IWbemClassObject **ppOutParams
)
{
	HRESULT hr = S_OK;
	IWbemClassObject *pInParamsDef = NULL;
	IWbemClassObject *pClassInst = NULL;
	
	do {
		ULONG i;

		if (cArgs == 0)
		{
			hr = E_INVALIDARG;
			break;
		}

		hr = pClass->lpVtbl->GetMethod(pClass,
			MethodName,
			0,
			&pInParamsDef,
			NULL);
		if (hr != S_OK)
			break;

		hr = pInParamsDef->lpVtbl->SpawnInstance(pInParamsDef,
			0,
			&pClassInst);
		if (hr != S_OK)
		{
			pInParamsDef->lpVtbl->Release(pInParamsDef);
			break;
		}

		for (i = 0; i < cArgs; i++)
		{
			hr = pClassInst->lpVtbl->Put(pClassInst, 
				pArgNames[i],
				0,
				pArgs[i],
				0);
			if (hr != S_OK)
				break;
		}

	} while (FALSE);

	if (hr == S_OK)
	{
		IWbemClassObject *pOutParams = NULL;

		hr = pServ->lpVtbl->ExecMethod(pServ,
			ObjPath,
			MethodName,
			0,
			NULL,
			pClassInst,
			&pOutParams,
			NULL);
		if (hr == S_OK)
		{
			*ppOutParams = pOutParams;
		}
		
	}

	if (pInParamsDef)
		pInParamsDef->lpVtbl->Release(pInParamsDef);

	if (pClassInst)
		pClassInst->lpVtbl->Release(pClassInst);

	return hr;
}

HRESULT GetAdapterConfigPath(IWbemClassObject *pAdaptCfg, BSTR *pStr)
{
	HRESULT hr;
	VARIANT index;
	WCHAR wszPath[MAX_PATH];
	BSTR lpPath;

	hr = pAdaptCfg->lpVtbl->Get(pAdaptCfg, L"Index", 0, &index, NULL, NULL);
	if (hr != S_OK)
		return hr;

	swprintf_s(wszPath, MAX_PATH, L"Win32_NetworkAdapterConfiguration.Index='%u'", index.uintVal);

	VariantClear(&index);

	lpPath = SysAllocString(wszPath);
	if (lpPath)
	{
		*pStr = lpPath;
		return S_OK;
	}

	return E_OUTOFMEMORY;
}

HRESULT SetDNSServerSearchOrder(
	IWbemServices *pServ, 
	BSTR ObjPath,
	DnsHost *aIp, 
	const ULONG cIp
)
{
	HRESULT hr;
	LPWSTR argNames = L"DNSServerSearchOrder";
	BSTR className = NULL;
	BSTR methodName;
	VARIANT ipAddresses;
	IWbemClassObject *pAdaptCfg;

	className = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	if (!className)
	{
		return E_OUTOFMEMORY;
	}

	hr = pServ->lpVtbl->GetObject(pServ, className, 0, NULL, &pAdaptCfg, NULL);
	if (hr != S_OK)
	{
		return hr;
	}

	hr = CreateIpArrayVariantV4(&ipAddresses, aIp, cIp);
	if (hr == S_OK)
	{
		methodName = SysAllocString(L"SetDNSServerSearchOrder");
		if (methodName)
		{
			VARIANT *args[1];
			IWbemClassObject *pOutParams = NULL;

			args[0]= &ipAddresses;

			hr = WbemExecMethod(pServ, 
				pAdaptCfg, 
				ObjPath,
				methodName,
				&argNames,
				args,
				1,
				&pOutParams);
			if (hr == S_OK)
			{
				VARIANT varRet;

				hr = pOutParams->lpVtbl->Get(pOutParams,
					L"ReturnValue", 0, &varRet, NULL, NULL);
				if (hr == S_OK)
				{
					if (varRet.uintVal == 0)
					{
						hr = S_OK;
					}
					else
					{
						hr = HRESULT_FROM_WIN32(varRet.uintVal);
					}

					VariantClear(&varRet);
				}

				pOutParams->lpVtbl->Release(pOutParams);
			}

			SysFreeString(methodName);
		}
		else
		{
			hr = E_OUTOFMEMORY;
		}

		VariantClear(&ipAddresses);
	}

	SysFreeString(className);
	pAdaptCfg->lpVtbl->Release(pAdaptCfg);
	return hr;
}

DnsServConf *GetIP4DnsServerList(LPCWSTR lpCfgPath)
{
	WCHAR fullPath[MAX_PATH];
	ULONG size;
	DnsServConf *pDnsConf;
	DnsHost *pHost;

	size = sizeof(*pDnsConf) + 2 * sizeof(DnsHost);
	pDnsConf = calloc(1, size);
	if (!pDnsConf)
		return NULL;

	pDnsConf->num_host = 2;
	pDnsConf->host = (DnsHost *)(pDnsConf + 1);
	pHost = pDnsConf->host;

	swprintf_s(fullPath, MAX_PATH, L"%s\\%s", lpCfgPath, CONF_FILENAME);
	size = GetPrivateProfileStringW(L"Preferred", L"v4addr", NULL, pHost->name, 64, fullPath);
	if (!size)
		goto error;

	pHost++;
	size = GetPrivateProfileStringW(L"Spared", L"v4addr", NULL, pHost->name, 64, fullPath);
	if (!size)
		goto error;

	return pDnsConf;

error:

	free(pDnsConf);

	return NULL;
}

int main(void)
{
	HRESULT hr;
	ComInstance instance;
	IWbemClassObject *pAdaptCfg = NULL;
	WSADATA wsd;
	WCHAR wszAddr[MAX_PATH];
	GUID guidAdapt;
	DWORD adaptIfIndex;

	if (WSAStartup(MAKEWORD(2, 0), &wsd))
		return -1;

	// Win32_NetworkAdapterConfiguration
	if (S_OK != CoInitializeEx(NULL, COINIT_MULTITHREADED))
		goto done;

	if (S_OK != ComInstanceInit(&instance, SYSMGR_NAMESPACE))
		goto done;

	/*hr = GetWbemClassInstance(&instance, L"Win32_NetworkAdapter", &objInstance);
	if (hr != S_OK)
		goto done; */

	if (0 == LocalHostIpv4String(wszAddr, MAX_PATH))
		goto done;

	if (NO_ERROR == GetAdapterGuidByAddr(wszAddr, &guidAdapt, &adaptIfIndex))
	{
		if (S_OK == FindAdapterClassById(instance.services, &guidAdapt, &pAdaptCfg))
		{
			DnsServConf *pDnsConf = NULL;
			DnsServConf *pDnsToSet;
			WCHAR path[MAX_PATH];
			BSTR objPath = NULL;

			GetCurrentDirectoryW(MAX_PATH, path);
			if (pDnsToSet = GetIP4DnsServerList(path))
			{
				
				hr = GetAdapterConfigPath(pAdaptCfg, &objPath);
				if (hr == S_OK)
				{
					hr = SetDNSServerSearchOrder(instance.services, objPath, pDnsToSet->host, pDnsToSet->num_host);
					SysFreeString(objPath);

					if (hr == S_OK)
					{
						printf("Configuration done:\n");
						for (int i = 0; i < pDnsToSet->num_host; i++)
						{
							printf("%ws\n", pDnsToSet->host[i].name);
						}
					}
				}

				free(pDnsToSet);
			}

			pAdaptCfg->lpVtbl->Release(pAdaptCfg);
		}
	}

	ComInstanceRelease(&instance);

done:

	WSACleanup();

	CoUninitialize();

	return 0;
}
