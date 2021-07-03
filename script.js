function log(msg)
{
	send({name: 'log', payload: msg});
	recv('ack', function () {}).wait();
}

const ptrCopyFileA = Module.getExportByName("kernel32.dll", "CopyFileA");
var funcCopyFileA = new NativeFunction(ptrCopyFileA, 'bool', ['pointer','pointer', 'bool']);

const ptrSleep = Module.getExportByName("kernel32.dll", "Sleep");
var funcSleep = new NativeFunction(ptrSleep, 'void', ['int']);

/*const ptrNtLoadDriver = Module.getExportByName("ntdll.dll", "NtLoadDriver");
Interceptor.attach(ptrNtLoadDriver, {
	onEnter:
		function (args)
		{
			log('=========================== NtLoadDriver ===========================');
			log('[*] Called NtLoadDriver!! [' + ptrNtLoadDriver + ']');
			log('[*] _IN_ PUNICODE_STRING DriverServiceName => [' + args[0] + ']');
		},
	
	onLeave:
		function (retval)
		{
			log('[*] NtLoadDriver Leave');
		}
});*/

const ptrStartServiceA = Module.getExportByName("Advapi32.dll", "StartServiceA");
var funcStartServiceA = new NativeFunction(ptrStartServiceA, 'bool', ['pointer', 'uint', 'pointer']);
Interceptor.replace(ptrStartServiceA,
	new NativeCallback(
		function(hService, dwNumServiceArgs, lpServiceArgVectors)
		{
			log('=========================== StartServiceA ===========================');
			log('[*] lpServiceArgVectors => ' + Memory.readAnsiString(lpServiceArgVectors));
		}
		, 'bool', ['pointer', 'uint', 'pointer']
	)
);

const ptrCreateServiceA = Module.getExportByName("Advapi32.dll", "CreateServiceA");
var funcCreateServiceA = new NativeFunction(ptrCreateServiceA, 'pointer', ['pointer', 'pointer', 'pointer', 'uint', 'uint', 'uint', 'uint', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
Interceptor.replace(ptrCreateServiceA,
	new NativeCallback(
		function(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword)
		{
			log('=========================== CreateServiceA ===========================');
			log('[*] Called StartServiceA!! [' + ptrCreateServiceA + ']');
			log('[*] lpServiceName => ' + Memory.readAnsiString(lpServiceName));
			log('[*] lpDisplayName => ' + Memory.readAnsiString(lpDisplayName));
			log('[*] dwDesiredAccess => ' + dwDesiredAccess);
			log('[*] dwServiceType => ' + dwServiceType);
			log('[*] dwStartType => ' + dwStartType);
			log('[*] dwErrorControl => ' + dwErrorControl);
			log('[*] lpBinaryPathName => ' + Memory.readAnsiString(lpBinaryPathName));
			log('[*] lpLoadOrderGroup => ' + Memory.readAnsiString(lpLoadOrderGroup));
			log('[*] lpdwTagId => ' + lpdwTagId);
			log('[*] lpServiceStartName => ' + Memory.readAnsiString(lpServiceStartName));
			log('[*] lpDependencies => ' + Memory.readAnsiString(lpDependencies));
			log('[*] lpPassword => ' + Memory.readAnsiString(lpPassword));

			var str_lpBinaryPathName = Memory.readAnsiString(lpBinaryPathName);
			var newPath = Memory.allocAnsiString("c:\\" + str_lpBinaryPathName.split('\\').reverse()[0]);
			log('[*] newPath => ' + Memory.readAnsiString(newPath));
			funcCopyFileA(lpBinaryPathName, newPath, 1);

			funcCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);

			log('[*] time to get to sleep...!');
			funcSleep(30000);
			log('[*] time to wake up...!');
		}
		, 'pointer', ['pointer', 'pointer', 'pointer', 'uint', 'uint', 'uint', 'uint', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
	)
);