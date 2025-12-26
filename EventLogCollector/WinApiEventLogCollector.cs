using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

sealed class WinApiEventLogCollector : EventLogCollectorBase
{
    private const int EvtQueryChannelPath = 0x1;
    private const int EvtQueryFilePath = 0x2;
    private const int EvtRenderEventXml = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNoMoreItems = 259;
    private const int DefaultBatchSize = 32;

    public override string CollectorName => "WinAPI (wevtapi.dll)";

    protected override IEnumerable<string> ReadEventXml(
        Options options,
        string xpathQuery,
        Stopwatch swRead,
        Stopwatch swRegex)
    {
        var queryPath = string.IsNullOrWhiteSpace(options.EvtxPath) ? options.LogName : options.EvtxPath;
        var flags = string.IsNullOrWhiteSpace(options.EvtxPath) ? EvtQueryChannelPath : EvtQueryFilePath;

        using var resultSet = EvtQuery(IntPtr.Zero, queryPath, xpathQuery, flags);
        if (resultSet.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "EvtQuery failed.");
        }

        var handles = new IntPtr[DefaultBatchSize];

        while (true)
        {
            swRead.Start();
            var success = EvtNext(resultSet, handles.Length, handles, 0, 0, out var returned);
            swRead.Stop();

            if (!success)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrorNoMoreItems)
                {
                    break;
                }

                throw new Win32Exception(error, "EvtNext failed.");
            }

            for (var i = 0; i < returned; i++)
            {
                using var evtHandle = new SafeEvtHandle(handles[i], ownsHandle: true);
                handles[i] = IntPtr.Zero;

                swRead.Start();
                var xml = RenderEventXml(evtHandle);
                swRead.Stop();

                yield return xml;
            }
        }
    }

    private static string RenderEventXml(SafeEvtHandle evtHandle)
    {
        if (EvtRender(IntPtr.Zero, evtHandle, EvtRenderEventXml, 0, IntPtr.Zero, out var bufferUsed, out _))
        {
            return string.Empty;
        }

        var error = Marshal.GetLastWin32Error();
        if (error != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(error, "EvtRender failed to get buffer size.");
        }

        var buffer = Marshal.AllocHGlobal(bufferUsed);
        try
        {
            if (!EvtRender(IntPtr.Zero, evtHandle, EvtRenderEventXml, bufferUsed, buffer, out bufferUsed, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "EvtRender failed.");
            }

            var charCount = Math.Max(0, (bufferUsed / 2) - 1);
            return Marshal.PtrToStringUni(buffer, charCount) ?? string.Empty;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("wevtapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeEvtHandle EvtQuery(IntPtr session, string path, string query, int flags);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtNext(SafeEvtHandle resultSet, int eventArraySize, IntPtr[] events, int timeout, int flags, out int returned);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtRender(IntPtr context, SafeEvtHandle fragment, int flags, int bufferSize, IntPtr buffer, out int bufferUsed, out int propertyCount);

    [DllImport("wevtapi.dll")]
    private static extern bool EvtClose(IntPtr handle);

    private sealed class SafeEvtHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeEvtHandle()
            : base(true)
        {
        }

        public SafeEvtHandle(IntPtr handle, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return EvtClose(handle);
        }
    }
}
