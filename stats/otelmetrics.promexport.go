package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"

	// To support rate limiting metrics export
	"unsafe"
	"github.com/cilium/ebpf"
)

var (
	ctx 				context.Context
	attribs				[]attribute.KeyValue
	counterValues		map[*api.Int64Counter]*OtelCounterValue
	gaugeValues			map[*api.Float64ObservableGauge]*OtelGaugeValue
	gaugeValuesMutex 	sync.RWMutex

	NFStartCount  *api.Int64Counter
	NFStopCount   *api.Int64Counter
	NFUpdateCount *api.Int64Counter
	NFRunning     *api.Float64ObservableGauge
	NFStartTime   *api.Float64ObservableGauge
	NFMonitorMap  *api.Float64ObservableGauge

	NFRlRecvCount *api.Float64ObservableGauge
	NFRlDropCount *api.Float64ObservableGauge
)

func SetupMetrics(hostname, daemonName, metricsAddr string) {
	ctx = context.Background()

	exporter, err := prometheus.New()
	if err != nil {
		log.Fatal(err)
	}
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	meter := provider.Meter("microsoft.com/lsg/lidt/ebpfmanagement")

	go serveMetrics(metricsAddr)

	attribs = []attribute.KeyValue {
		attribute.Key("Organization").String("LSG"),
		attribute.Key("Team").String("LIDT"),
		attribute.Key("Project").String("eBPFManagement"),
	}

	counterValues = make(map[*api.Int64Counter]*OtelCounterValue)
	metricName := daemonName + "_OtelNFStartCount"
	startCount, err := meter.Int64Counter(metricName, api.WithDescription("The count of network functions started"))
	if err != nil {
		log.Fatal(err)
	}
	NFStartCount = &startCount
	counterValues[NFStartCount] = NewCounterValue(metricName, attribs)

	metricName = daemonName + "_OtelNFStopCount"
	stopCount, err := meter.Int64Counter(metricName, api.WithDescription("The count of network functions stopped"))
	if err != nil {
		log.Fatal(err)
	}
	NFStopCount = &stopCount
	counterValues[NFStopCount] = NewCounterValue(metricName, attribs)

	metricName = daemonName + "_OtelNFUpdateCount"
	updateCount, err := meter.Int64Counter(metricName, api.WithDescription("The count of network functions updated"))
	if err != nil {
		log.Fatal(err)
	}
	NFUpdateCount = &updateCount
	counterValues[NFUpdateCount] = NewCounterValue(metricName, attribs)

	gaugeValues = make(map[*api.Float64ObservableGauge]*OtelGaugeValue)
	metricName = daemonName + "_OtelNFRunning"
	runningGugage, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates network functions is running or not"))
	if err != nil {
		log.Fatal(err)
	}
	NFRunning = &runningGugage
	gaugeValues[NFRunning] = NewGaugeValue(metricName, attribs)

	metricName = daemonName + "_OtelNFStartTime"
	startTimeGuage, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates start time of the network function since unix epoch in seconds"))
	if err != nil {
		log.Fatal(err)
	}
	NFStartTime = &startTimeGuage
	gaugeValues[NFStartTime] = NewGaugeValue(metricName, attribs)

	metricName = daemonName + "_OtelNFMonitorMap"
	monitorMapGuage, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates network function monitor counters"))
	if err != nil {
		log.Fatal(err)
	}
	NFMonitorMap = &monitorMapGuage
	gaugeValues[NFMonitorMap] = NewGaugeValue(metricName, attribs)

	metricName = daemonName + "_RLRecvCount"
	NFRlRecvCountGauge, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates network packets received by the rate limiter"))
	if err != nil {
		log.Fatal(err)
	}
	NFRlRecvCount = &NFRlRecvCountGauge
	gaugeValues[NFRlRecvCount] = NewGaugeValue(metricName, attribs)

	metricName = daemonName + "_RLDropCount"
	NFRlDropCountGauge, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates network packets dropped by the rate limiter"))
	if err != nil {
		log.Fatal(err)
	}
	NFRlDropCount = &NFRlDropCountGauge
	gaugeValues[NFRlDropCount] = NewGaugeValue(metricName, attribs)

	for gauge, gaugeVal := range gaugeValues {
		gaugeCopy := gauge
		valCopy := gaugeVal
		_, err = meter.RegisterCallback(func(_ context.Context, o api.Observer) error {
			gaugeValuesMutex.RLock()
			defer gaugeValuesMutex.RUnlock()

			o.ObserveFloat64(*gaugeCopy, valCopy.GetValue(), valCopy.GetMeasurementOptions())
			return nil
		}, *gaugeCopy)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func serveMetrics(metricsAddr string) {
	log.Printf("serving metrics at %s/metrics", metricsAddr)
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(metricsAddr, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func GeteBPFMapValue(mapFullName string) uint64 {
	var mpId ebpf.MapID = 0
	// mapFullName := "rl_drop_count_map"
	mpName := mapFullName[:15]

	for {
		tmpMapId, err := ebpf.MapGetNextID(mpId)
		if err != nil {
			log.Printf("failed to fetch to map object %v", err)
			return 0
		}

		ebpfMap, err := ebpf.NewMapFromID(tmpMapId)
		if err != nil {
			log.Printf("failed to get NewMapFromID %v", err)
			return 0
		}
		defer ebpfMap.Close()

		ebpfInfo, err := ebpfMap.Info()
		if err != nil {
			log.Printf("failed to fetch ebpfinfo %v", err)
			return 0
		}

		if ebpfInfo.Name == mpName {
			// log.Printf("===> Found target map for %v", mpName)

			var key uint64
			var value uint64
			if err := ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
				log.Printf("failed to lookup map: %v", err)
				break
			}

			return value
			// log.Printf("GeteBPFMapValue: %v content value: %v", mapFullName, value)
			// newValue := value + 1
			
			// if err := ebpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&newValue), ebpf.UpdateAny); err != nil {
			// 	log.Printf("failed to update map: %v", err)
			// }

			// stats.UpdateExecveStat(newValue)
			
			// break
		}

		mpId = tmpMapId
	}

	return 0
}

func Incr(counterVec *api.Int64Counter, ebpfProgram, direction, ifaceName string) {
	localAttributes := map[string]string {
		"dbpfProgram": ebpfProgram,
		"direction": direction,
		"ifaceName": ifaceName,
	}

	counter := counterValues[counterVec]
	counter.SetAttributes(localAttributes)

	(*counterVec).Add(ctx, 1, counter.GetMeasurementOptions())

	if err := sendToAgent(counter, "/counter"); err != nil {
		log.Println(err)
	}
}

func Set(value float64, gaugeVec *api.Float64ObservableGauge, ebpfProgram, direction, ifaceName string) {
	localAttributes := map[string]string {
		"ebpfProgram": ebpfProgram,
		"ifaceName": ifaceName,
	}
	updateGaugeValue(value, gaugeVec, localAttributes)
}

func SetValue(value float64, gaugeVec *api.Float64ObservableGauge, ebpfProgram, mapName, ifaceName string) {
	localAttributes := map[string]string {
		"ebpfProgram": ebpfProgram,
		"mapName": mapName,
		"ifaceName": ifaceName,
	}
	updateGaugeValue(value, gaugeVec, localAttributes)

	processMonitoredMapValueUpdate(value, gaugeVec, localAttributes, mapName)
}

func SetWithVersion(value float64, gaugeVec *api.Float64ObservableGauge, ebpfProgram, version, direction, ifaceName string) {
	localAttributes := map[string]string {
		"ebpfProgram": ebpfProgram,
		"version": version,
		"direction": direction,
		"ifaceName": ifaceName,
	}
	updateGaugeValue(value, gaugeVec, localAttributes)
}

func updateGaugeValue(value float64, gauge *api.Float64ObservableGauge, localAttributes map[string]string) {
	gaugeValuesMutex.Lock()
	defer gaugeValuesMutex.Unlock()

	gaugeObj := gaugeValues[gauge]
	gaugeObj.SetValue(value)
	gaugeObj.SetAttributes(localAttributes)

	if err := sendToAgent(gaugeObj, "/gauge"); err != nil {
		log.Println(err)
	}
}

func processMonitoredMapValueUpdate(value float64, GaugeVec * api.Float64ObservableGauge, localAttributes map[string]string, mapName string) {
	if GaugeVec != NFMonitorMap {
		return
	}

	var targetGauge *api.Float64ObservableGauge = nil
	if strings.HasPrefix(mapName, "rl_recv_count_map") {
		targetGauge = NFRlRecvCount
	} else if strings.HasPrefix(mapName, "rl_drop_count_map") {
		targetGauge = NFRlDropCount
	} else {
		return
	}

	// value passed in from caller for rl_recv_count_map gets reset to 0
	// for unknown reason. Adding temporary workaround to retrieve actual
	// values from eBPF map instead.
	// mapValue := GeteBPFMapValue(mapName)
	updateGaugeValue(value, targetGauge, localAttributes)
}

const AGENTURL string = "http://localhost"
const AGENTPORT int = 8897

func sendToAgent(data any, route string) error {
	jsonContent, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to serialize data: %v", err)
	}

	url := fmt.Sprintf("%s:%d%s", AGENTURL, AGENTPORT, route)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonContent))
	if err != nil {
		return fmt.Errorf("POST request to agent failed: %v", err)
	}
	defer resp.Body.Close()

	return nil
}