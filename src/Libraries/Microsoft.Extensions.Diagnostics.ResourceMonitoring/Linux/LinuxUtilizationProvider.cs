// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Shared.Instruments;

namespace Microsoft.Extensions.Diagnostics.ResourceMonitoring.Linux;

internal sealed class LinuxUtilizationProvider : ISnapshotProvider
{
    private const double One = 1.0;
    private const long Hundred = 100L;
    private const double CpuLimitThreshold110Percent = 1.1;

    // Meters to track CPU utilization threshold exceedances
    private readonly Counter<long>? _cpuUtilizationLimit100PercentExceededCounter;
    private readonly Counter<long>? _cpuUtilizationLimit110PercentExceededCounter;
    private double _cpuLimit = double.NaN;
    private double _cpuRequest = double.NaN;
    private long _cpuTotalPeriodsP;

    private readonly object _cpuLocker = new();
    private readonly object _memoryLocker = new();
    private readonly ILogger<LinuxUtilizationProvider> _logger;
    private readonly ILinuxUtilizationParser _parser;
    private readonly ulong _memoryLimit;
    private readonly TimeSpan _cpuRefreshInterval;
    private readonly TimeSpan _memoryRefreshInterval;
    private readonly TimeProvider _timeProvider;
    private readonly double _scaleRelativeToCpuLimit;
    private readonly double _scaleRelativeToCpuRequest;
    private readonly double _scaleRelativeToCpuRequestForTrackerApi;

    private DateTimeOffset _refreshAfterCpu;
    private DateTimeOffset _refreshAfterCpuP;
    private DateTimeOffset _refreshAfterMemory;

    // Track the actual timestamp when we read CPU values
    private DateTimeOffset _lastCpuMeasurementTime;
    private DateTimeOffset _lastCpuMeasurementTimeP;

    private double _cpuPercentage = double.NaN;
    private double _lastCpuCoresUsed = double.NaN;
    private double _lastCpuCoresUsedByPeriodsP = double.NaN;
    private long _cgroupCpuUsageP;
    private long _previousCgroupCpuUsageP;
    private long _cgroupCpuPeriodP;
    private long _previousCgroupCpuPeriodP;
    private double _memoryPercentage;
    private long _previousCgroupCpuTime;
    private long _previousHostCpuTime;
    private long _cpuUtilizationLimit100PercentExceeded;
    private long _cpuUtilizationLimit110PercentExceeded;
    public SystemResources Resources { get; }

    public LinuxUtilizationProvider(IOptions<ResourceMonitoringOptions> options, ILinuxUtilizationParser parser,
        IMeterFactory meterFactory, ILogger<LinuxUtilizationProvider>? logger = null, TimeProvider? timeProvider = null)
    {
        _parser = parser;
        _logger = logger ?? NullLogger<LinuxUtilizationProvider>.Instance;
        _timeProvider = timeProvider ?? TimeProvider.System;
        DateTimeOffset now = _timeProvider.GetUtcNow();
        _cpuRefreshInterval = options.Value.CpuConsumptionRefreshInterval;
        _memoryRefreshInterval = options.Value.MemoryConsumptionRefreshInterval;
        _refreshAfterCpu = now;
        _refreshAfterCpuP = now;
        _refreshAfterMemory = now;
        _memoryLimit = _parser.GetAvailableMemoryInBytes();
        _previousHostCpuTime = _parser.GetHostCpuUsageInNanoseconds();
        _previousCgroupCpuTime = _parser.GetCgroupCpuUsageInNanoseconds();
        _lastCpuMeasurementTime = now;
        _lastCpuMeasurementTimeP = now;

        float hostCpus = _parser.GetHostCpuCount();
        float cpuLimit = _parser.GetCgroupLimitedCpus();
        float cpuRequest = _parser.GetCgroupRequestCpu();
        _scaleRelativeToCpuLimit = hostCpus / cpuLimit;
        _scaleRelativeToCpuRequest = hostCpus / cpuRequest;
        _scaleRelativeToCpuRequestForTrackerApi = hostCpus; // the division by cpuRequest is performed later on in the ResourceUtilization class

#pragma warning disable CA2000 // Dispose objects before losing scope
        // We don't dispose the meter because IMeterFactory handles that
        // An issue on analyzer side: https://github.com/dotnet/roslyn-analyzers/issues/6912
        // Related documentation: https://github.com/dotnet/docs/pull/37170
        var meter = meterFactory.Create(ResourceUtilizationInstruments.MeterName);
#pragma warning restore CA2000 // Dispose objects before losing scope

        if (options.Value.CalculateCpuUsageWithoutHostDelta)
        {
            _previousCgroupCpuTime = _parser.GetCgroupCpuUsageInNanosecondsV2();
            cpuLimit = _parser.GetCgroupLimitV2();

            // Try to get the CPU request from cgroup
            cpuRequest = _parser.GetCgroupRequestCpuV2();
            _cpuLimit = cpuLimit;
            _cpuRequest = cpuRequest;
            _cpuTotalPeriodsP = _parser.GetCgroupPeriodsIntervalV2();
            (_previousCgroupCpuUsageP, _previousCgroupCpuPeriodP) = _parser.GetCpuUsageAndPeriods();
            // Initialize the counters
            _cpuUtilizationLimit100PercentExceededCounter = meter.CreateCounter<long>("cpu_utilization_limit_100_percent_exceeded");
            _cpuUtilizationLimit110PercentExceededCounter = meter.CreateCounter<long>("cpu_utilization_limit_110_percent_exceeded");
            _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ContainerCpuLimitUtilization, observeValue: () => CpuUtilizationLimit(cpuLimit), unit: "1");
            _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ContainerCpuLimitUtilizationByPeriods, observeValue: () => CpuUtilizationWithoutHostDeltaUsingPeriods(_cpuTotalPeriodsP) / cpuLimit, unit: "1");
            _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ContainerCpuRequestUtilization, observeValue: () => CpuUtilizationWithoutHostDelta() / cpuRequest, unit: "1");
        }
        else
        {
            _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ContainerCpuLimitUtilization, observeValue: () => CpuUtilization() * _scaleRelativeToCpuLimit, unit: "1");
            _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ContainerCpuRequestUtilization, observeValue: () => CpuUtilization() * _scaleRelativeToCpuRequest, unit: "1");
            _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ProcessCpuUtilization, observeValue: () => CpuUtilization() * _scaleRelativeToCpuRequest, unit: "1");
        }

        _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ContainerMemoryLimitUtilization, observeValue: MemoryUtilization, unit: "1");
        _ = meter.CreateObservableGauge(name: ResourceUtilizationInstruments.ProcessMemoryUtilization, observeValue: MemoryUtilization, unit: "1");

        // cpuRequest is a CPU request (aka guaranteed number of CPU units) for pod, for host its 1 core
        // cpuLimit is a CPU limit (aka max CPU units available) for a pod or for a host.
        // _memoryLimit - Resource Memory Limit (in k8s terms)
        // _memoryLimit - To keep the contract, this parameter will get the Host available memory
        Resources = new SystemResources(cpuRequest, cpuLimit, _memoryLimit, _memoryLimit);
        Log.SystemResourcesInfo(_logger, cpuLimit, cpuRequest, _memoryLimit, _memoryLimit);
    }

    public double CpuUtilizationWithoutHostDeltaUsingPeriods(long cpuPeriodsSlice)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        lock (_cpuLocker)
        {
            if (now < _refreshAfterCpuP)
            {
                Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDeltaUsingPeriods - Using cached value: {_lastCpuCoresUsedByPeriodsP}, Now: {now}, RefreshAfter: {_refreshAfterCpuP}");
                return _lastCpuCoresUsedByPeriodsP;
            }
        }

        var (cpuUsage, cpuPeriod) = _parser.GetCpuUsageAndPeriods();
        _cgroupCpuUsageP = cpuUsage;
        _cgroupCpuPeriodP = cpuPeriod;
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDeltaUsingPeriods - cpuUsage={_cgroupCpuUsageP}, cpuPeriod={_cgroupCpuPeriodP}");

        lock (_cpuLocker)
        {
            if (now >= _refreshAfterCpuP)
            {
                long deltaCgroup = _cgroupCpuUsageP - _previousCgroupCpuUsageP;
                long deltaCpuPeriodsRecorded = _cgroupCpuPeriodP - _previousCgroupCpuPeriodP;
                long deltaCpuPeriodInNanoseconds = deltaCpuPeriodsRecorded * cpuPeriodsSlice * 1000;
                Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDeltaUsingPeriods - deltaCgroup={deltaCgroup}, deltaCpuPeriodInNanoseconds={deltaCpuPeriodInNanoseconds}");
                
                if (deltaCgroup > 0)
                {
                    double coresUsed = deltaCgroup / (double) deltaCpuPeriodInNanoseconds;

                    Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDeltaUsingPeriods -  Start: now={now}, lastMeasurement={_lastCpuMeasurementTimeP}, elapsed={deltaCpuPeriodInNanoseconds}ns, cgroupCpuUsageP={_cgroupCpuUsageP}, previous={_previousCgroupCpuUsageP}, Calculated cores used: {coresUsed} (delta={deltaCgroup})");

                    _lastCpuCoresUsedByPeriodsP = coresUsed;
                    _refreshAfterCpuP = now.Add(_cpuRefreshInterval);
                    _previousCgroupCpuUsageP = _cgroupCpuUsageP;
                    _previousCgroupCpuPeriodP = _cgroupCpuPeriodP;

                    // Update the timestamp for next calculation
                    _lastCpuMeasurementTimeP = now;
                }
                else {
                    Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDeltaUsingPeriods - No change in CPU time (delta={deltaCgroup})");
                }
            }
        }

        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDeltaUsingPeriods - Result: {_lastCpuCoresUsedByPeriodsP}");
        return _lastCpuCoresUsedByPeriodsP;
    }

    public double CpuUtilizationWithoutHostDelta()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        double actualElapsedNanoseconds = (now - _lastCpuMeasurementTime).TotalNanoseconds;

        lock (_cpuLocker)
        {
            if (now < _refreshAfterCpu)
            {
                Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDelta - Using cached value: {_lastCpuCoresUsed}");
                return _lastCpuCoresUsed;
            }
        }

        long cgroupCpuTime = _parser.GetCgroupCpuUsageInNanosecondsV2();

        lock (_cpuLocker)
        {
            if (now >= _refreshAfterCpu)
            {
                long deltaCgroup = cgroupCpuTime - _previousCgroupCpuTime;

                if (deltaCgroup > 0)
                {
                    double coresUsed = deltaCgroup / actualElapsedNanoseconds;

                    Log.CpuUsageDataV2(_logger, cgroupCpuTime, _previousCgroupCpuTime, actualElapsedNanoseconds, coresUsed);
                    Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDelta -  Start: now={now}, lastMeasurement={_lastCpuMeasurementTime}, elapsed={actualElapsedNanoseconds}ns, cgroupCpuTime={cgroupCpuTime}, previous={_previousCgroupCpuTime}, Calculated cores used: {coresUsed} (delta={deltaCgroup})");

                    _lastCpuCoresUsed = coresUsed;
                    _refreshAfterCpu = now.Add(_cpuRefreshInterval);
                    _previousCgroupCpuTime = cgroupCpuTime;

                    // Update the timestamp for next calculation
                    _lastCpuMeasurementTime = now;
                }
                else {
                    Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDelta - No change in CPU time (delta={deltaCgroup})");
                }
            }
        }

        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilizationWithoutHostDelta - Result: {_lastCpuCoresUsed}");
        return _lastCpuCoresUsed;
    }

    /// <summary>
    /// Calculates CPU utilization relative to the CPU limit.
    /// </summary>
    /// <param name="cpuLimit">The CPU limit to use for the calculation.</param>
    /// <returns>CPU usage as a ratio of the limit.</returns>
    public double CpuUtilizationLimit(float cpuLimit)
    {
        double utilization = CpuUtilizationWithoutHostDelta() / cpuLimit;

        // Increment counter if utilization exceeds 1 (100%)
        if (utilization > 1.0)
        {
            _cpuUtilizationLimit100PercentExceededCounter?.Add(1);
            _cpuUtilizationLimit100PercentExceeded++;
            Log.CounterMessage100(_logger, _cpuUtilizationLimit100PercentExceeded);
        }

        // Increment counter if utilization exceeds 110%
        if (utilization > CpuLimitThreshold110Percent)
        {
            _cpuUtilizationLimit110PercentExceededCounter?.Add(1);
            _cpuUtilizationLimit110PercentExceeded++;
            Log.CounterMessage110(_logger, _cpuUtilizationLimit110PercentExceeded);
        }

        return utilization;
    }

    public double CpuUtilization()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - Start: now={now}");

        lock (_cpuLocker)
        {
            if (now < _refreshAfterCpu)
            {
                Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - Using cached value: {_cpuPercentage}");
                return _cpuPercentage;
            }
        }

        long hostCpuTime = _parser.GetHostCpuUsageInNanoseconds();
        long cgroupCpuTime = _parser.GetCgroupCpuUsageInNanoseconds();
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - hostCpuTime={hostCpuTime}, cgroupCpuTime={cgroupCpuTime}");
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - previous values: hostCpu={_previousHostCpuTime}, cgroupCpu={_previousCgroupCpuTime}");

        lock (_cpuLocker)
        {
            if (now >= _refreshAfterCpu)
            {
                long deltaHost = hostCpuTime - _previousHostCpuTime;
                long deltaCgroup = cgroupCpuTime - _previousCgroupCpuTime;
                Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - deltaHost={deltaHost}, deltaCgroup={deltaCgroup}");

                if (deltaHost > 0 && deltaCgroup > 0)
                {
                    double percentage = Math.Min(One, (double)deltaCgroup / deltaHost);
                    Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - Calculated percentage: {percentage} (deltaCgroup/deltaHost={(double)deltaCgroup / deltaHost})");

                    Log.CpuUsageData(_logger, cgroupCpuTime, hostCpuTime, _previousCgroupCpuTime, _previousHostCpuTime, percentage);

                    _cpuPercentage = percentage;
                    _refreshAfterCpu = now.Add(_cpuRefreshInterval);
                    _previousCgroupCpuTime = cgroupCpuTime;
                    _previousHostCpuTime = hostCpuTime;
                }
                else {
                    Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - No valid delta values (deltaHost={deltaHost}, deltaCgroup={deltaCgroup})");
                }
            }
        }

        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} CpuUtilization - Result: {_cpuPercentage}");
        return _cpuPercentage;
    }

    public double MemoryUtilization()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();

        lock (_memoryLocker)
        {
            if (now < _refreshAfterMemory)
            {
                return _memoryPercentage;
            }
        }

        ulong memoryUsed = _parser.GetMemoryUsageInBytes();

        lock (_memoryLocker)
        {
            if (now >= _refreshAfterMemory)
            {
                double memoryPercentage = Math.Min(One, (double)memoryUsed / _memoryLimit);

                _memoryPercentage = memoryPercentage;
                _refreshAfterMemory = now.Add(_memoryRefreshInterval);
            }
        }

        Log.MemoryUsageData(_logger, memoryUsed, _memoryLimit, _memoryPercentage);

        return _memoryPercentage;
    }

    public double ContainerCpuLimitUtilization()
    {
        double cpuUtilization = CpuUtilizationWithoutHostDelta();
        double result = cpuUtilization / _cpuLimit;
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} ContainerCpuLimitUtilization - CPU utilization: {cpuUtilization}, CPU limit: {_cpuLimit}, Result: {result}");
        return result;
    }

    public double ContainerCpuRequestUtilization()
    {
        double cpuUtilization = CpuUtilizationWithoutHostDelta();
        double result = cpuUtilization / _cpuRequest;
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} ContainerCpuRequestUtilization - CPU utilization: {cpuUtilization}, CPU request: {_cpuRequest}, Result: {result}");
        return result;
    }

    public double ProcessCpuUtilizationWithoutHostDelta()
    {
        double cpuUtilization = CpuUtilizationWithoutHostDelta();
        double result = cpuUtilization / _cpuRequest;
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} ProcessCpuUtilizationWithoutHostDelta - CPU utilization: {cpuUtilization}, CPU request: {_cpuRequest}, Result: {result}");
        return result;
    }

    /// <remarks>
    /// Not adding caching, to preserve original semantics of the code.
    /// The snapshot provider is called in intervals configured by the tracker.
    /// We multiply by scale to make hardcoded algorithm in tracker's calculator to produce right results.
    /// </remarks>
    public Snapshot GetSnapshot()
    {
        long hostTime = _parser.GetHostCpuUsageInNanoseconds();
        long cgroupTime = _parser.GetCgroupCpuUsageInNanoseconds();
        ulong memoryUsed = _parser.GetMemoryUsageInBytes();

        return new Snapshot(
            totalTimeSinceStart: TimeSpan.FromTicks(hostTime / Hundred),
            kernelTimeSinceStart: TimeSpan.Zero,
            userTimeSinceStart: TimeSpan.FromTicks((long)(cgroupTime / Hundred * _scaleRelativeToCpuRequestForTrackerApi)),
            memoryUsageInBytes: memoryUsed);
    }
}
